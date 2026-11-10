//! Passive UPDATE decoding. Invalid input is never converted into a withdrawal.
use crate::model::{AddressFamily, CanonicalPrefix};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("BGP UPDATE: {0}")]
pub struct UpdateError(pub String);
type Result<T> = std::result::Result<T, UpdateError>;

#[derive(Clone, Copy)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(UpdateError("truncated field".into()));
        }
        let v = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeContext {
    pub asn_width: u8,
    #[serde(default)]
    pub add_path: BTreeSet<AddressFamily>,
}
impl Default for DecodeContext {
    fn default() -> Self {
        Self {
            asn_width: 4,
            add_path: BTreeSet::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSegment {
    /// 1=set, 2=sequence, 3=confederation sequence, 4=confederation set.
    pub kind: u8,
    pub asns: Vec<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAttribute {
    pub flags: u8,
    pub code: u8,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attributes {
    pub origin: Option<u8>,
    pub path: Vec<PathSegment>,
    pub next_hops: Vec<String>,
    pub raw: Vec<RawAttribute>,
    pub warnings: Vec<String>,
}
impl Attributes {
    pub fn origin_asn(&self) -> Option<u32> {
        if !self.warnings.is_empty() {
            return None;
        }
        self.path
            .iter()
            .rev()
            .find(|s| s.kind == 1 || s.kind == 2)
            .filter(|s| s.kind == 2)
            .and_then(|s| s.asns.last().copied())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nlri {
    pub prefix: CanonicalPrefix,
    pub path_id: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update {
    pub attributes: Attributes,
    pub announcements: Vec<Nlri>,
    pub withdrawals: Vec<Nlri>,
}

pub fn prefix(c: &mut Cursor<'_>, family: AddressFamily) -> Result<CanonicalPrefix> {
    let bits = c.u8()?;
    let max = if family == AddressFamily::Ipv4 {
        32
    } else {
        128
    };
    if bits > max {
        return Err(UpdateError("invalid NLRI prefix length".into()));
    }
    let len = usize::from(bits).div_ceil(8);
    let mut b = [0u8; 16];
    b[..len].copy_from_slice(c.take(len)?);
    if bits % 8 != 0 {
        b[len - 1] &= 0xff << (8 - bits % 8);
    }
    let text = if family == AddressFamily::Ipv4 {
        format!("{}/{}", Ipv4Addr::new(b[0], b[1], b[2], b[3]), bits)
    } else {
        format!("{}/{}", Ipv6Addr::from(b), bits)
    };
    text.parse().map_err(|e| UpdateError(format!("{e}")))
}
pub fn nlri(data: &[u8], family: AddressFamily, add_path: bool) -> Result<Vec<Nlri>> {
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let path_id = if add_path { Some(c.u32()?) } else { None };
        out.push(Nlri {
            prefix: prefix(&mut c, family)?,
            path_id,
        });
    }
    Ok(out)
}
fn path(data: &[u8], width: u8) -> Result<Vec<PathSegment>> {
    if !matches!(width, 2 | 4) {
        return Err(UpdateError("ASN width must be 2 or 4".into()));
    }
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let kind = c.u8()?;
        let n = c.u8()?;
        if !(1..=4).contains(&kind) || n == 0 {
            return Err(UpdateError("invalid AS_PATH segment".into()));
        }
        let mut asns = Vec::new();
        for _ in 0..n {
            asns.push(if width == 4 {
                c.u32()?
            } else {
                u32::from(c.u16()?)
            });
        }
        out.push(PathSegment { kind, asns });
    }
    Ok(out)
}
fn path_count(p: &[PathSegment]) -> usize {
    p.iter()
        .map(|s| match s.kind {
            1 => 1,
            2 => s.asns.len(),
            _ => 0,
        })
        .sum()
}
fn reconstruct(old: &[PathSegment], new: &[PathSegment]) -> Option<Vec<PathSegment>> {
    if new.iter().any(|s| s.kind > 2) || path_count(new) > path_count(old) {
        return None;
    }
    let mut keep = path_count(old) - path_count(new);
    let mut out = Vec::new();
    for s in old {
        if keep == 0 {
            break;
        }
        let mut s = s.clone();
        match s.kind {
            1 => keep -= 1,
            2 => {
                s.asns.truncate(keep);
                keep -= s.asns.len();
            }
            _ => {}
        }
        out.push(s);
    }
    out.extend_from_slice(new);
    Some(out)
}
fn family(afi: u16, safi: u8) -> Option<AddressFamily> {
    match (afi, safi) {
        (1, 1) => Some(AddressFamily::Ipv4),
        (2, 1) => Some(AddressFamily::Ipv6),
        _ => None,
    }
}
fn next_hops(data: &[u8], fam: AddressFamily) -> Result<Vec<String>> {
    match (fam, data.len()) {
        (AddressFamily::Ipv4, 4) => Ok(vec![
            Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        ]),
        (AddressFamily::Ipv6, 16 | 32) => Ok(data
            .chunks_exact(16)
            .map(|b| {
                let mut v = [0; 16];
                v.copy_from_slice(b);
                Ipv6Addr::from(v).to_string()
            })
            .collect()),
        _ => Err(UpdateError("unsupported next-hop length or family".into())),
    }
}
/// RIB attributes use RFC 6396's abbreviated MP_REACH representation.
pub fn decode_attributes(
    data: &[u8],
    ctx: &DecodeContext,
    rib: Option<AddressFamily>,
) -> Result<Update> {
    let mut c = Cursor::new(data);
    let mut attrs = Attributes::default();
    let mut seen = BTreeSet::new();
    let mut announcements = Vec::new();
    let mut withdrawals = Vec::new();
    let mut as4 = None;
    while c.remaining() > 0 {
        let flags = c.u8()?;
        let code = c.u8()?;
        let len = if flags & 0x10 != 0 {
            usize::from(c.u16()?)
        } else {
            usize::from(c.u8()?)
        };
        let bytes = c.take(len)?;
        if !seen.insert(code) {
            return Err(UpdateError(format!("duplicate attribute {code}")));
        }
        let expected = match code {
            1..=3 => Some(0x40),
            4 | 14 | 15 => Some(0x80),
            5 | 6 => Some(0x40),
            7 | 8 | 17 | 18 | 32 => Some(0xc0),
            _ => None,
        };
        if expected.is_some_and(|e| flags & 0xc0 != e) {
            return Err(UpdateError(format!("invalid flags for attribute {code}")));
        }
        attrs.raw.push(RawAttribute {
            flags,
            code,
            value: bytes.to_vec(),
        });
        match code {
            1 => {
                if bytes.len() != 1 || bytes[0] > 2 {
                    return Err(UpdateError("invalid ORIGIN".into()));
                }
                attrs.origin = Some(bytes[0]);
            }
            2 => attrs.path = path(bytes, ctx.asn_width)?,
            3 => attrs
                .next_hops
                .extend(next_hops(bytes, AddressFamily::Ipv4)?),
            17 => as4 = Some(path(bytes, 4)?),
            14 | 15 => {
                let mut p = Cursor::new(bytes);
                if let Some(f) = rib {
                    if code == 14 {
                        let n = usize::from(p.u8()?);
                        attrs.next_hops.extend(next_hops(p.take(n)?, f)?);
                        if p.remaining() != 0 {
                            return Err(UpdateError("trailing RIB MP_REACH bytes".into()));
                        }
                    } else {
                        attrs.warnings.push("MP_UNREACH in RIB".into());
                    }
                    continue;
                }
                let afi = p.u16()?;
                let safi = p.u8()?;
                let Some(f) = family(afi, safi) else {
                    attrs
                        .warnings
                        .push(format!("unsupported AFI/SAFI {afi}/{safi}"));
                    continue;
                };
                if code == 14 {
                    let n = usize::from(p.u8()?);
                    attrs.next_hops.extend(next_hops(p.take(n)?, f)?);
                    p.u8()?;
                }
                let routes = nlri(p.take(p.remaining())?, f, ctx.add_path.contains(&f))?;
                if code == 14 {
                    announcements.extend(routes);
                } else {
                    withdrawals.extend(routes);
                }
            }
            4 | 5 if bytes.len() != 4 => {
                return Err(UpdateError(format!("invalid attribute {code} length")));
            }
            _ => {
                if expected.is_none() && flags & 0x80 == 0 {
                    attrs
                        .warnings
                        .push(format!("unknown well-known attribute {code}"));
                }
            }
        }
    }
    if ctx.asn_width == 2
        && let Some(as4) = as4
    {
        match reconstruct(&attrs.path, &as4) {
            Some(p) => attrs.path = p,
            None => attrs
                .warnings
                .push("AS4_PATH cannot reconstruct AS_PATH".into()),
        }
    }
    Ok(Update {
        attributes: attrs,
        announcements,
        withdrawals,
    })
}
pub fn decode_update(body: &[u8], ctx: &DecodeContext) -> Result<Update> {
    if body.len() > 4077 {
        return Err(UpdateError("extended BGP messages are unsupported".into()));
    }
    let mut c = Cursor::new(body);
    let n = usize::from(c.u16()?);
    let withdraw = nlri(
        c.take(n)?,
        AddressFamily::Ipv4,
        ctx.add_path.contains(&AddressFamily::Ipv4),
    )?;
    let n = usize::from(c.u16()?);
    let mut u = decode_attributes(c.take(n)?, ctx, None)?;
    let ipv4 = nlri(
        c.take(c.remaining())?,
        AddressFamily::Ipv4,
        ctx.add_path.contains(&AddressFamily::Ipv4),
    )?;
    if !ipv4.is_empty() && !u.attributes.raw.iter().any(|a| a.code == 3) {
        return Err(UpdateError("announcement missing NEXT_HOP".into()));
    }
    u.announcements.extend(ipv4);
    u.withdrawals.extend(withdraw);
    if !u.announcements.is_empty()
        && (u.attributes.origin.is_none() || !u.attributes.raw.iter().any(|a| a.code == 2))
    {
        return Err(UpdateError("announcement missing ORIGIN or AS_PATH".into()));
    }
    Ok(u)
}
