//! Offline BGP capture inspection. Capabilities and message boundaries are never guessed.
use crate::{
    Error, Result,
    bundle::{BundleWriter, read_bounded},
    model::*,
    mrt::observations,
    tcp::TcpStream,
};
use bgp_hijack_core::{
    codec::{Capability, ControlMessage, FrameDecoder, MessageType, OpenMessage, decode_control},
    model::AddressFamily,
    update::{DecodeContext, decode_update},
};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, PcapBlockOwned, PcapError};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    net::IpAddr,
    path::Path,
};
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowKey {
    pub section: u32,
    pub interface: u32,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}
impl FlowKey {
    fn reverse(&self) -> Self {
        Self {
            section: self.section,
            interface: self.interface,
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContext {
    pub flow: FlowKey,
    pub asn_width: u8,
    #[serde(default)]
    pub add_path: BTreeSet<AddressFamily>,
    pub first_bgp_sequence: Option<u32>,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFile {
    pub schema_version: u32,
    pub sessions: Vec<SessionContext>,
}
pub fn load_context(path: &Path) -> Result<ContextFile> {
    let bytes = read_bounded(path, 1024 * 1024)?;
    let s = std::str::from_utf8(&bytes).map_err(|e| Error::Invalid(e.to_string()))?;
    let file: ContextFile =
        serde_saphyr::from_str(s).map_err(|e| Error::Invalid(format!("session context: {e}")))?;
    if file.schema_version != 1 {
        return Err(Error::Invalid("unsupported session context schema".into()));
    }
    let mut seen = BTreeSet::new();
    for c in &file.sessions {
        if !matches!(c.asn_width, 2 | 4) || !seen.insert(c.flow.clone()) {
            return Err(Error::Invalid(
                "duplicate flow or invalid ASN width in session context".into(),
            ));
        }
    }
    Ok(file)
}
struct Flow {
    tcp: TcpStream,
    decoder: FrameDecoder,
    open: Option<OpenMessage>,
    epoch: u64,
    initial: Option<u32>,
    failed: bool,
    refs: BTreeSet<String>,
}
pub struct CaptureDecoder {
    flows: BTreeMap<FlowKey, Flow>,
    contexts: BTreeMap<FlowKey, SessionContext>,
    next_epoch: u64,
    source: String,
}
impl CaptureDecoder {
    pub fn new(source: String, contexts: ContextFile) -> Self {
        Self {
            flows: BTreeMap::new(),
            contexts: contexts
                .sessions
                .into_iter()
                .map(|c| (c.flow.clone(), c))
                .collect(),
            next_epoch: 0,
            source,
        }
    }
    fn source(&self, key: &FlowKey, epoch: u64) -> Source {
        Source {
            source: self.source.clone(),
            collector: Some(format!(
                "section:{} interface:{}",
                key.section, key.interface
            )),
            peer: format!(
                "{}:{} -> {}:{}",
                key.source, key.source_port, key.destination, key.destination_port
            ),
            epoch,
        }
    }
    pub fn packet(
        &mut self,
        link: i32,
        section: u32,
        interface: u32,
        time: Option<f64>,
        bytes: &[u8],
        writer: &mut BundleWriter,
    ) -> Result<()> {
        let packet = match link {
            1 => SlicedPacket::from_ethernet(bytes),
            113 => SlicedPacket::from_linux_sll(bytes),
            101 | 228 | 229 => SlicedPacket::from_ip(bytes),
            276 => {
                if bytes.len() < 20 {
                    return Err(Error::Invalid("truncated SLL2 header".into()));
                }
                SlicedPacket::from_ether_type(
                    etherparse::EtherType(u16::from_be_bytes([bytes[0], bytes[1]])),
                    &bytes[20..],
                )
            }
            _ => {
                return Err(Error::Invalid(format!(
                    "unsupported capture linktype {link}"
                )));
            }
        }
        .map_err(|e| Error::Invalid(format!("packet header: {e}")))?;
        if packet.is_ip_payload_fragmented() {
            return Err(Error::Invalid("IP fragmentation is unsupported".into()));
        }
        let (source, destination) = match &packet.net {
            Some(NetSlice::Ipv4(ip)) => (
                IpAddr::V4(ip.header().source_addr()),
                IpAddr::V4(ip.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(ip)) => (
                IpAddr::V6(ip.header().source_addr()),
                IpAddr::V6(ip.header().destination_addr()),
            ),
            _ => return Ok(()),
        };
        let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
            return Ok(());
        };
        let key = FlowKey {
            section,
            interface,
            source,
            source_port: tcp.source_port(),
            destination,
            destination_port: tcp.destination_port(),
        };
        if tcp.source_port() != 179
            && tcp.destination_port() != 179
            && !self.contexts.contains_key(&key)
        {
            return Ok(());
        }
        let reference = writer.evidence(bytes)?;
        if tcp.syn()
            && self
                .flows
                .get(&key)
                .is_some_and(|f| f.initial != Some(tcp.sequence_number()))
        {
            self.close(&key, writer)?;
            self.close(&key.reverse(), writer)?;
        }
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= writer.limits().flows {
                return Err(Error::Limit("capture flow count".into()));
            }
            self.next_epoch += 1;
            let context = self.contexts.get(&key);
            let first = if tcp.syn() {
                Some(tcp.sequence_number().wrapping_add(1))
            } else {
                context.and_then(|c| c.first_bgp_sequence)
            };
            self.flows.insert(
                key.clone(),
                Flow {
                    tcp: TcpStream::new(first, writer.limits().stream_bytes),
                    decoder: FrameDecoder::default(),
                    open: None,
                    epoch: self.next_epoch,
                    initial: tcp.syn().then_some(tcp.sequence_number()),
                    failed: false,
                    refs: BTreeSet::new(),
                },
            );
        }
        if self.flows[&key].failed {
            return Ok(());
        }
        let reverse_open = self.flows.get(&key.reverse()).and_then(|f| f.open.clone());
        let explicit = self.contexts.get(&key).map(|c| DecodeContext {
            asn_width: c.asn_width,
            add_path: c.add_path.clone(),
        });
        let source = self.source(&key, self.flows[&key].epoch);
        let result = (|| -> Result<()> {
            let flow = self.flows.get_mut(&key).expect("inserted flow");
            if flow.refs.len() >= 4096 {
                return Err(Error::Limit(
                    "capture evidence references per stream".into(),
                ));
            }
            flow.refs.insert(reference.clone());
            let mut data = tcp.payload();
            let mut seq = tcp.sequence_number().wrapping_add(u32::from(tcp.syn()));
            // An explicit boundary may skip bytes before the first full BGP message.
            if let Some(start) = self.contexts.get(&key).and_then(|c| c.first_bgp_sequence) {
                let skip = start.wrapping_sub(seq) as i32;
                if skip > 0 {
                    let n = (skip as usize).min(data.len());
                    data = &data[n..];
                    seq = seq.wrapping_add(n as u32);
                }
            }
            let contiguous = flow.tcp.push(seq, data)?;
            let mut rest = contiguous.as_slice();
            while !rest.is_empty() {
                let (used, frame) = flow
                    .decoder
                    .consume(rest)
                    .map_err(|e| Error::Invalid(e.to_string()))?;
                rest = &rest[used..];
                if let Some(frame) = frame {
                    let refs = flow.refs.iter().cloned().collect::<Vec<_>>();
                    match frame.kind() {
                        MessageType::Open => {
                            let ControlMessage::Open(open) = decode_control(&frame)
                                .map_err(|e| Error::Invalid(e.to_string()))?
                            else {
                                unreachable!()
                            };
                            flow.open = Some(open);
                        }
                        MessageType::Update => {
                            let negotiated = flow
                                .open
                                .as_ref()
                                .zip(reverse_open.as_ref())
                                .map(|(a, b)| negotiate(a, b))
                                .transpose()?;
                            if negotiated
                                .as_ref()
                                .zip(explicit.as_ref())
                                .is_some_and(|(a, b)| a != b)
                            {
                                return Err(Error::Invalid(
                                    "session context conflicts with captured OPEN capabilities"
                                        .into(),
                                ));
                            }
                            let ctx = negotiated.or_else(|| explicit.clone()).ok_or_else(|| {
                                Error::Invalid(
                                    "missing OPEN negotiation or explicit session context".into(),
                                )
                            })?;
                            let update = decode_update(frame.body(), &ctx)?;
                            for event in observations(update, source.clone(), time) {
                                writer.record(event, refs.clone())?;
                            }
                        }
                        MessageType::Notification => {
                            writer.record(
                                Observation::SourceStatus {
                                    source: source.clone(),
                                    status: "notification".into(),
                                },
                                refs,
                            )?;
                        }
                        _ => {}
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.flows.get_mut(&key).expect("flow").failed = true;
            writer.record(
                Observation::Gap {
                    source: Some(source),
                    reason: e.to_string(),
                },
                vec![reference],
            )?;
        }
        if tcp.fin() || tcp.rst() {
            self.close(&key, writer)?;
            self.close(&key.reverse(), writer)?;
        }
        Ok(())
    }
    fn close(&mut self, key: &FlowKey, writer: &mut BundleWriter) -> Result<()> {
        if let Some(mut flow) = self.flows.remove(key) {
            let source = self.source(key, flow.epoch);
            if flow.tcp.finish().is_err() || flow.decoder.finish().is_err() {
                writer.record(
                    Observation::Gap {
                        source: Some(source.clone()),
                        reason: "capture stream ended with incomplete TCP/BGP data".into(),
                    },
                    flow.refs.iter().cloned().collect(),
                )?;
            }
            writer.record(
                Observation::SourceStatus {
                    source,
                    status: "capture_end".into(),
                },
                vec![],
            )?;
        }
        Ok(())
    }
    pub fn finish(&mut self, writer: &mut BundleWriter) -> Result<()> {
        for key in self.flows.keys().cloned().collect::<Vec<_>>() {
            self.close(&key, writer)?;
        }
        Ok(())
    }
}
fn add_paths(open: &OpenMessage) -> Result<BTreeMap<AddressFamily, u8>> {
    let mut out = BTreeMap::new();
    for cap in &open.capabilities {
        if let Capability::Unknown { code: 69, value } = cap {
            if value.len() % 4 != 0 {
                return Err(Error::Invalid("malformed ADD-PATH capability".into()));
            }
            for b in value.chunks_exact(4) {
                let f = match (u16::from_be_bytes([b[0], b[1]]), b[2]) {
                    (1, 1) => AddressFamily::Ipv4,
                    (2, 1) => AddressFamily::Ipv6,
                    _ => continue,
                };
                if !(1..=3).contains(&b[3]) || out.insert(f, b[3]).is_some_and(|v| v != b[3]) {
                    return Err(Error::Invalid("conflicting ADD-PATH capability".into()));
                }
            }
        }
    }
    Ok(out)
}
fn negotiate(sender: &OpenMessage, receiver: &OpenMessage) -> Result<DecodeContext> {
    for open in [sender, receiver] {
        let asns = open
            .capabilities
            .iter()
            .filter_map(|c| {
                if let Capability::FourOctetAsn(a) = c {
                    Some(a.0)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        if asns.len() > 1 {
            return Err(Error::Invalid(
                "conflicting four-octet ASN capabilities".into(),
            ));
        }
    }
    let four = |o: &OpenMessage| {
        o.capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAsn(_)))
    };
    let a = add_paths(sender)?;
    let b = add_paths(receiver)?;
    let add_path = a
        .into_iter()
        .filter(|(f, m)| m & 2 != 0 && b.get(f).is_some_and(|n| n & 1 != 0))
        .map(|(f, _)| f)
        .collect();
    Ok(DecodeContext {
        asn_width: if four(sender) && four(receiver) { 4 } else { 2 },
        add_path,
    })
}
pub fn inspect(path: &Path, contexts: ContextFile, writer: &mut BundleWriter) -> Result<()> {
    let file = File::open(path)?;
    if file.metadata()?.len() > writer.limits().input_bytes {
        return Err(Error::Limit("capture input size".into()));
    }
    let mut reader = pcap_parser::create_reader(writer.limits().record_bytes, file)
        .map_err(|e| Error::Invalid(format!("capture header: {e}")))?;
    let mut decoder = CaptureDecoder::new(path.display().to_string(), contexts);
    let mut interfaces = Vec::new();
    let mut section = 0;
    let mut legacy = (1, 1_000_000.0);
    let mut offset = 0u64;
    loop {
        writer.check_cancelled()?;
        match reader.next() {
            Ok((size, block)) => {
                let mut packet = None;
                match block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy = (
                            h.network.0,
                            if h.is_nanosecond_precision() {
                                1_000_000_000.0
                            } else {
                                1_000_000.0
                            },
                        );
                    }
                    PcapBlockOwned::Legacy(p) => {
                        if p.caplen < p.origlen {
                            writer.gap(format!("truncated packet at offset {offset}"))?;
                        }
                        packet = Some((
                            legacy.0,
                            0,
                            Some(f64::from(p.ts_sec) + f64::from(p.ts_usec) / legacy.1),
                            p.data,
                        ));
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        decoder.finish(writer)?;
                        interfaces.clear();
                        section += 1;
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(i)) => {
                        if interfaces.len() >= 1024 {
                            return Err(Error::Limit("PCAPNG interfaces".into()));
                        }
                        let resolution = i.ts_resolution().ok_or_else(|| {
                            Error::Invalid("unsupported timestamp resolution".into())
                        })?;
                        interfaces.push((i.linktype.0, resolution, i.ts_offset()));
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
                        let &(link, resolution, offset_time) = interfaces
                            .get(p.if_id as usize)
                            .ok_or_else(|| Error::Invalid("missing PCAPNG interface".into()))?;
                        if p.caplen < p.origlen {
                            writer.gap(format!("truncated packet at offset {offset}"))?;
                        }
                        if p.caplen as usize > p.data.len() {
                            return Err(Error::Invalid("packet caplen exceeds block".into()));
                        }
                        let time = offset_time as f64
                            + (((u64::from(p.ts_high) << 32) | u64::from(p.ts_low)) as f64)
                                / resolution as f64;
                        packet = Some((link, p.if_id, Some(time), &p.data[..p.caplen as usize]));
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => writer.gap(
                        "PCAPNG simple packets have no timestamp; unsupported in this release",
                    )?,
                    _ => {}
                }
                if let Some((link, iface, time, data)) = packet
                    && let Err(e) = decoder.packet(link, section, iface, time, data, writer)
                {
                    match e {
                        Error::Io(_) | Error::Limit(_) => return Err(e),
                        _ => writer.gap(format!("packet at offset {offset}: {e}"))?,
                    }
                }
                reader.consume(size);
                offset += size as u64;
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| Error::Invalid(format!("capture refill: {e}")))?;
            }
            Err(e) => return Err(Error::Invalid(format!("capture offset {offset}: {e}"))),
        }
    }
    decoder.finish(writer)
}
