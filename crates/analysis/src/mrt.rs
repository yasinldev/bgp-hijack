//! Streaming RFC 6396/8050 envelopes. No resynchronization after corrupt lengths.
use crate::{Error, Result, bundle::BundleWriter, model::*};
use bgp_hijack_core::{
    codec::{Frame, MessageType},
    model::AddressFamily,
    update::{self, Cursor, DecodeContext},
};
use std::{
    fs::File,
    io::{BufReader, Read},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
#[derive(Clone)]
struct Peer {
    address: String,
    asn: u32,
}
pub struct MrtDecoder {
    peers: Vec<Peer>,
    collector: Option<String>,
    source: String,
    epoch: u64,
    pub skipped: u64,
}
impl MrtDecoder {
    pub fn new(source: String) -> Self {
        Self {
            peers: Vec::new(),
            collector: None,
            source,
            epoch: 0,
            skipped: 0,
        }
    }
    pub fn decode(
        &mut self,
        typ: u16,
        sub: u16,
        timestamp: f64,
        body: &[u8],
    ) -> Result<Vec<Observation>> {
        if body.len() > 1024 * 1024 {
            return Err(Error::Limit("MRT record".into()));
        }
        let mut c = Cursor::new(body);
        if typ == 13 && sub == 1 {
            self.epoch += 1;
            self.peers.clear();
            let id = ipv4(c.take(4)?);
            let n = usize::from(c.u16()?);
            let view = String::from_utf8_lossy(c.take(n)?);
            self.collector = Some(format!("{id}/{view}"));
            let count = usize::from(c.u16()?);
            for _ in 0..count {
                let flags = c.u8()?;
                if flags & !3 != 0 {
                    return Err(Error::Invalid("MRT peer flags".into()));
                }
                c.take(4)?;
                let address = address(&mut c, if flags & 1 != 0 { 2 } else { 1 })?;
                let asn = if flags & 2 != 0 {
                    c.u32()?
                } else {
                    u32::from(c.u16()?)
                };
                self.peers.push(Peer { address, asn });
            }
            if c.remaining() != 0 {
                return Err(Error::Invalid("trailing peer index bytes".into()));
            }
            return Ok(vec![]);
        }
        if typ == 13 && matches!(sub, 2 | 4 | 8 | 10) {
            c.u32()?;
            let fam = if matches!(sub, 2 | 8) {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            };
            let prefix = update::prefix(&mut c, fam)?;
            let count = c.u16()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let index = usize::from(c.u16()?);
                let originated = c.u32()?;
                let path_id = if sub >= 8 { Some(c.u32()?) } else { None };
                let n = usize::from(c.u16()?);
                let attrs =
                    update::decode_attributes(c.take(n)?, &DecodeContext::default(), Some(fam))?
                        .attributes;
                if attrs.origin.is_none() || !attrs.raw.iter().any(|a| a.code == 2) {
                    return Err(Error::Invalid("RIB route missing ORIGIN or AS_PATH".into()));
                }
                let peer = self.peers.get(index).ok_or_else(|| {
                    Error::Invalid("MRT RIB references missing peer index".into())
                })?;
                let source = Source {
                    source: self.source.clone(),
                    collector: self.collector.clone(),
                    peer: format!("{} AS{}", peer.address, peer.asn),
                    epoch: self.epoch,
                };
                // Snapshot time is comparable across entries; originated time is retained in raw evidence.
                let _ = originated;
                out.push(Observation::Route(RouteObservation {
                    source,
                    source_time: Some(timestamp),
                    prefix,
                    address_family: prefix.family(),
                    path_id,
                    action: RouteAction::Announce,
                    attributes: attrs,
                }));
            }
            if c.remaining() != 0 {
                return Err(Error::Invalid("trailing RIB bytes".into()));
            }
            return Ok(out);
        }
        if matches!(typ, 16 | 17) && matches!(sub, 0 | 1 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11) {
            let time = if typ == 17 {
                let micros = c.u32()?;
                if micros >= 1_000_000 {
                    return Err(Error::Invalid("MRT microseconds".into()));
                }
                timestamp + f64::from(micros) / 1_000_000.0
            } else {
                timestamp
            };
            let as4 = matches!(sub, 4 | 5 | 7 | 9 | 11);
            let peer_asn = if as4 { c.u32()? } else { u32::from(c.u16()?) };
            if as4 {
                c.u32()?;
            } else {
                c.u16()?;
            }
            c.u16()?;
            let afi = c.u16()?;
            let peer = address(&mut c, afi)?;
            let local = address(&mut c, afi)?;
            let source = Source {
                source: self.source.clone(),
                collector: Some(local),
                peer: format!("{peer} AS{peer_asn}"),
                epoch: self.epoch,
            };
            if matches!(sub, 0 | 5) {
                c.u16()?;
                let state = c.u16()?;
                if c.remaining() != 0 {
                    return Err(Error::Invalid("trailing MRT state bytes".into()));
                }
                return Ok(vec![Observation::SourceStatus {
                    source,
                    status: if state == 6 { "up" } else { "down" }.into(),
                }]);
            }
            let frame = Frame::from_bytes(c.take(c.remaining())?)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if frame.kind() != MessageType::Update {
                return Ok(vec![]);
            }
            let mut ctx = DecodeContext {
                asn_width: if as4 { 4 } else { 2 },
                ..Default::default()
            };
            if sub >= 8 {
                ctx.add_path
                    .extend([AddressFamily::Ipv4, AddressFamily::Ipv6]);
            }
            let u = update::decode_update(frame.body(), &ctx)?;
            return Ok(observations(u, source, Some(time)));
        }
        self.skipped += 1;
        Ok(vec![Observation::Gap {
            source: None,
            reason: format!("unsupported MRT type/subtype {typ}/{sub}"),
        }])
    }
}
pub fn observations(u: update::Update, source: Source, time: Option<f64>) -> Vec<Observation> {
    let mut out = Vec::new();
    for warning in &u.attributes.warnings {
        out.push(Observation::Gap {
            source: Some(source.clone()),
            reason: warning.clone(),
        });
    }
    for (action, routes) in [
        (RouteAction::Withdraw, u.withdrawals),
        (RouteAction::Announce, u.announcements),
    ] {
        for n in routes {
            out.push(Observation::Route(RouteObservation {
                source: source.clone(),
                source_time: time,
                prefix: n.prefix,
                address_family: n.prefix.family(),
                path_id: n.path_id,
                action: action.clone(),
                attributes: u.attributes.clone(),
            }));
        }
    }
    out
}
fn ipv4(b: &[u8]) -> String {
    Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
}
fn address(c: &mut Cursor<'_>, afi: u16) -> Result<String> {
    match afi {
        1 => Ok(ipv4(c.take(4)?)),
        2 => {
            let mut b = [0; 16];
            b.copy_from_slice(c.take(16)?);
            Ok(Ipv6Addr::from(b).to_string())
        }
        _ => Err(Error::Invalid(format!("unsupported MRT peer AFI {afi}"))),
    }
}
/// A record iterator is public for fuzzing and does not allocate from unchecked lengths.
pub fn read_records<R: Read>(
    mut reader: R,
    writer: &mut BundleWriter,
    source: String,
) -> Result<()> {
    let mut decoder = MrtDecoder::new(source);
    let mut offset = 0u64;
    loop {
        writer.check_cancelled()?;
        let mut header = [0; 12];
        let n = reader.read(&mut header[..1])?;
        if n == 0 {
            break;
        }
        reader.read_exact(&mut header[1..])?;
        let timestamp = u32::from_be_bytes(header[..4].try_into().expect("header"));
        let typ = u16::from_be_bytes([header[4], header[5]]);
        let sub = u16::from_be_bytes([header[6], header[7]]);
        let len = u32::from_be_bytes(header[8..12].try_into().expect("header")) as usize;
        if len + 12 > writer.limits().record_bytes
            || offset + 12 + len as u64 > writer.limits().input_bytes
        {
            return Err(Error::Limit(format!("MRT record/input at offset {offset}")));
        }
        let mut bytes = header.to_vec();
        bytes.resize(12 + len, 0);
        reader.read_exact(&mut bytes[12..])?;
        let reference = writer.evidence(&bytes)?;
        match decoder.decode(typ, sub, f64::from(timestamp), &bytes[12..]) {
            Ok(events) => {
                for e in events {
                    writer.record(e, vec![reference.clone()])?;
                }
            }
            Err(e) => writer.record(
                Observation::Gap {
                    source: None,
                    reason: format!("MRT offset {offset}: {e}"),
                },
                vec![reference],
            )?,
        }
        offset += bytes.len() as u64;
    }
    Ok(())
}
pub fn inspect(path: &Path, writer: &mut BundleWriter) -> Result<()> {
    let mut probe = File::open(path)?;
    let mut magic = [0; 3];
    let n = probe.read(&mut magic)?;
    let f = BufReader::new(File::open(path)?);
    let reader: Box<dyn Read> = if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        Box::new(flate2::read::MultiGzDecoder::new(f))
    } else if n == 3 && magic == *b"BZh" {
        Box::new(bzip2::read::MultiBzDecoder::new(f))
    } else {
        Box::new(f)
    };
    read_records(reader, writer, path.display().to_string())
}
