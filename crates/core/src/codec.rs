//! Bounded BGP framing and control messages. No socket or route-state ownership.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::model::{AddressFamily, Asn};

pub const HEADER_LEN: usize = 19;
pub const MAX_MESSAGE_LEN: usize = 4096;
pub const AS_TRANS: u16 = 23456;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub code: u8,
    pub subcode: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("BGP marker must contain sixteen 0xff octets")]
    InvalidMarker,
    #[error("invalid BGP message length {0}")]
    InvalidLength(u16),
    #[error("unsupported BGP message type {0}")]
    InvalidMessageType(u8),
    #[error("truncated BGP message: received {received} of {expected} octets")]
    Truncated { received: usize, expected: usize },
    #[error("decoder is in a terminal error state")]
    DecoderFailed,
    #[error("decoder has already reached EOF")]
    DecoderFinished,
    #[error("unsupported BGP version {0}; expected 4")]
    UnsupportedVersion(u8),
    #[error("unacceptable hold time {0}; expected zero or at least three seconds")]
    InvalidHoldTime(u16),
    #[error("BGP identifier must be nonzero")]
    InvalidRouterId,
    #[error("malformed OPEN: {0}")]
    MalformedOpen(&'static str),
    #[error("unsupported OPEN optional parameter {kind}")]
    UnsupportedParameter { kind: u8, encoded: Vec<u8> },
    #[error("capability {code} has invalid length {length}")]
    InvalidCapabilityLength { code: u8, length: usize },
    #[error("outbound control message exceeds its encoding limit")]
    EncodingLimit,
    #[error("invalid outbound OPEN: {0}")]
    InvalidOutboundOpen(&'static str),
    #[error("UPDATE bodies are not implemented by the control-message codec")]
    UpdateNotImplemented,
}

impl CodecError {
    /// Wire action for a future session owner; local misuse/EOF has no notification.
    pub fn notification(&self) -> Option<NotificationMessage> {
        let (code, subcode, data) = match self {
            Self::InvalidMarker => (1, 1, vec![]),
            Self::InvalidLength(length) => (1, 2, length.to_be_bytes().to_vec()),
            Self::InvalidMessageType(kind) => (1, 3, vec![*kind]),
            Self::UnsupportedVersion(_) => (2, 1, vec![0, 4]),
            Self::InvalidHoldTime(_) => (2, 6, vec![]),
            Self::InvalidRouterId => (2, 3, vec![]),
            Self::UnsupportedParameter { encoded, .. } => (2, 4, encoded.clone()),
            Self::MalformedOpen(_) | Self::InvalidCapabilityLength { .. } => (2, 0, vec![]),
            _ => return None,
        };
        Some(NotificationMessage {
            code,
            subcode,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    kind: MessageType,
    body: Vec<u8>,
}

impl Frame {
    pub fn kind(&self) -> MessageType {
        self.kind
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = FrameDecoder::default();
        let (consumed, frame) = decoder.consume(bytes)?;
        decoder.finish()?;
        if consumed != bytes.len() {
            return Err(CodecError::InvalidLength(
                bytes.len().min(u16::MAX as usize) as u16,
            ));
        }
        frame.ok_or(CodecError::Truncated {
            received: 0,
            expected: HEADER_LEN,
        })
    }
}

/// Holds at most one 4096-octet message, even when consume receives a huge slice.
pub struct FrameDecoder {
    buffer: [u8; MAX_MESSAGE_LEN],
    used: usize,
    expected: usize,
    kind: Option<MessageType>,
    failed: bool,
    finished: bool,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_MESSAGE_LEN],
            used: 0,
            expected: HEADER_LEN,
            kind: None,
            failed: false,
            finished: false,
        }
    }
}

impl FrameDecoder {
    pub fn buffered_len(&self) -> usize {
        self.used
    }

    pub fn consume(&mut self, input: &[u8]) -> Result<(usize, Option<Frame>), CodecError> {
        if self.failed {
            return Err(CodecError::DecoderFailed);
        }
        if self.finished {
            return Err(CodecError::DecoderFinished);
        }
        let result = self.consume_inner(input);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn consume_inner(&mut self, input: &[u8]) -> Result<(usize, Option<Frame>), CodecError> {
        let mut consumed = 0;
        if self.kind.is_none() {
            let count = (HEADER_LEN - self.used).min(input.len());
            self.buffer[self.used..self.used + count].copy_from_slice(&input[..count]);
            self.used += count;
            consumed += count;
            if self.used < HEADER_LEN {
                return Ok((consumed, None));
            }
            let (kind, length) = header(&self.buffer[..HEADER_LEN])?;
            self.kind = Some(kind);
            self.expected = length;
        }
        let count = (self.expected - self.used).min(input.len() - consumed);
        self.buffer[self.used..self.used + count]
            .copy_from_slice(&input[consumed..consumed + count]);
        self.used += count;
        consumed += count;
        if self.used != self.expected {
            return Ok((consumed, None));
        }
        let frame = Frame {
            kind: self.kind.expect("validated header sets a message type"),
            body: self.buffer[HEADER_LEN..self.used].to_vec(),
        };
        self.used = 0;
        self.expected = HEADER_LEN;
        self.kind = None;
        Ok((consumed, Some(frame)))
    }

    pub fn finish(&mut self) -> Result<(), CodecError> {
        if self.failed {
            return Err(CodecError::DecoderFailed);
        }
        if self.used != 0 {
            self.failed = true;
            return Err(CodecError::Truncated {
                received: self.used,
                expected: self.expected,
            });
        }
        self.finished = true;
        Ok(())
    }
}

fn header(bytes: &[u8]) -> Result<(MessageType, usize), CodecError> {
    if bytes[..16] != [0xff; 16] {
        return Err(CodecError::InvalidMarker);
    }
    let length = u16::from_be_bytes([bytes[16], bytes[17]]);
    if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&usize::from(length)) {
        return Err(CodecError::InvalidLength(length));
    }
    let kind = match bytes[18] {
        1 => MessageType::Open,
        2 => MessageType::Update,
        3 => MessageType::Notification,
        4 => MessageType::Keepalive,
        other => return Err(CodecError::InvalidMessageType(other)),
    };
    let valid = match kind {
        MessageType::Open => length >= 29,
        MessageType::Update => length >= 23,
        MessageType::Notification => length >= 21,
        MessageType::Keepalive => length == 19,
    };
    if !valid {
        return Err(CodecError::InvalidLength(length));
    }
    Ok((kind, usize::from(length)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Multiprotocol { afi: u16, safi: u8 },
    FourOctetAsn(Asn),
    Unknown { code: u8, value: Vec<u8> },
}

impl Capability {
    pub fn unicast(family: AddressFamily) -> Self {
        Self::Multiprotocol {
            afi: match family {
                AddressFamily::Ipv4 => 1,
                AddressFamily::Ipv6 => 2,
            },
            safi: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// The received two-octet field. Four-octet capability is authoritative.
    pub my_as: u16,
    pub hold_time: u16,
    pub router_id: u32,
    pub capabilities: Vec<Capability>,
}

impl OpenMessage {
    pub fn new(asn: Asn, hold_time: u16, router_id: u32, families: &[AddressFamily]) -> Self {
        let mut capabilities = vec![Capability::FourOctetAsn(asn)];
        capabilities.extend(families.iter().copied().map(Capability::unicast));
        Self {
            my_as: u16::try_from(asn.0).unwrap_or(AS_TRANS),
            hold_time,
            router_id,
            capabilities,
        }
    }

    pub fn effective_asn(&self) -> Result<Asn, OpenCompatibilityError> {
        let mut found = None;
        for capability in &self.capabilities {
            if let Capability::FourOctetAsn(asn) = capability {
                if found.is_some_and(|old| old != *asn) {
                    return Err(OpenCompatibilityError::ConflictingAsns);
                }
                found = Some(*asn);
            }
        }
        found.ok_or(OpenCompatibilityError::MissingFourOctetAsn)
    }

    fn check_fields(&self) -> Result<(), CodecError> {
        if matches!(self.hold_time, 1 | 2) {
            return Err(CodecError::InvalidHoldTime(self.hold_time));
        }
        if self.router_id == 0 {
            return Err(CodecError::InvalidRouterId);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Open(OpenMessage),
    Keepalive,
    Notification(NotificationMessage),
}

pub fn decode_control(frame: &Frame) -> Result<ControlMessage, CodecError> {
    Ok(match frame.kind {
        MessageType::Open => ControlMessage::Open(decode_open(&frame.body)?),
        MessageType::Keepalive => ControlMessage::Keepalive,
        MessageType::Notification => ControlMessage::Notification(NotificationMessage {
            code: frame.body[0],
            subcode: frame.body[1],
            data: frame.body[2..].to_vec(),
        }),
        MessageType::Update => return Err(CodecError::UpdateNotImplemented),
    })
}

fn decode_open(body: &[u8]) -> Result<OpenMessage, CodecError> {
    if body[0] != 4 {
        return Err(CodecError::UnsupportedVersion(body[0]));
    }
    let mut open = OpenMessage {
        my_as: u16::from_be_bytes([body[1], body[2]]),
        hold_time: u16::from_be_bytes([body[3], body[4]]),
        router_id: u32::from_be_bytes(body[5..9].try_into().expect("four octets")),
        capabilities: Vec::new(),
    };
    open.check_fields()?;
    let extended = body[9] != 0 && body.get(10) == Some(&255);
    let (offset, length) = if extended {
        if body.len() < 13 {
            return Err(CodecError::MalformedOpen("truncated extended length"));
        }
        (13, usize::from(u16::from_be_bytes([body[11], body[12]])))
    } else {
        (10, usize::from(body[9]))
    };
    if length != body.len() - offset {
        return Err(CodecError::MalformedOpen(
            "optional-parameter length does not match body",
        ));
    }
    let mut params = &body[offset..];
    while !params.is_empty() {
        let header_len = if extended { 3 } else { 2 };
        if params.len() < header_len {
            return Err(CodecError::MalformedOpen("truncated parameter header"));
        }
        let len = if extended {
            usize::from(u16::from_be_bytes([params[1], params[2]]))
        } else {
            usize::from(params[1])
        };
        if len > params.len() - header_len {
            return Err(CodecError::MalformedOpen("parameter exceeds OPEN boundary"));
        }
        if params[0] != 2 {
            return Err(CodecError::UnsupportedParameter {
                kind: params[0],
                encoded: params[..header_len + len].to_vec(),
            });
        }
        let mut caps = &params[header_len..header_len + len];
        while !caps.is_empty() {
            if caps.len() < 2 {
                return Err(CodecError::MalformedOpen("truncated capability header"));
            }
            let (code, len) = (caps[0], usize::from(caps[1]));
            if len > caps.len() - 2 {
                return Err(CodecError::MalformedOpen(
                    "capability exceeds parameter boundary",
                ));
            }
            let value = &caps[2..2 + len];
            let capability = match code {
                1 | 65 if len != 4 => {
                    return Err(CodecError::InvalidCapabilityLength { code, length: len });
                }
                1 => Capability::Multiprotocol {
                    afi: u16::from_be_bytes([value[0], value[1]]),
                    safi: value[3],
                },
                65 => Capability::FourOctetAsn(Asn(u32::from_be_bytes(
                    value.try_into().expect("four octets"),
                ))),
                _ => Capability::Unknown {
                    code,
                    value: value.to_vec(),
                },
            };
            open.capabilities.push(capability);
            caps = &caps[2 + len..];
        }
        params = &params[header_len + len..];
    }
    Ok(open)
}

pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let (kind, body) = match message {
        ControlMessage::Open(open) => (MessageType::Open, encode_open(open)?),
        ControlMessage::Keepalive => (MessageType::Keepalive, vec![]),
        ControlMessage::Notification(notification) => {
            if notification.data.len() > MAX_MESSAGE_LEN - 21 {
                return Err(CodecError::EncodingLimit);
            }
            let mut body = vec![notification.code, notification.subcode];
            body.extend_from_slice(&notification.data);
            (MessageType::Notification, body)
        }
    };
    let length = HEADER_LEN + body.len();
    if length > MAX_MESSAGE_LEN {
        return Err(CodecError::EncodingLimit);
    }
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(&[0xff; 16]);
    output.extend_from_slice(&(length as u16).to_be_bytes());
    output.push(kind as u8);
    output.extend_from_slice(&body);
    Ok(output)
}

fn encode_open(open: &OpenMessage) -> Result<Vec<u8>, CodecError> {
    open.check_fields()?;
    let my_as = match open.effective_asn() {
        Ok(asn) => u16::try_from(asn.0).unwrap_or(AS_TRANS),
        Err(OpenCompatibilityError::MissingFourOctetAsn) => open.my_as,
        Err(_) => {
            return Err(CodecError::InvalidOutboundOpen(
                "conflicting ASN capabilities",
            ));
        }
    };
    let mut caps = Vec::new();
    for capability in &open.capabilities {
        let (code, value) = match capability {
            Capability::Multiprotocol { afi, safi } => {
                let [a, b] = afi.to_be_bytes();
                (1, vec![a, b, 0, *safi])
            }
            Capability::FourOctetAsn(asn) => (65, asn.0.to_be_bytes().to_vec()),
            Capability::Unknown { code: 1 | 65, .. } => {
                return Err(CodecError::InvalidOutboundOpen(
                    "known capability must use its typed variant",
                ));
            }
            Capability::Unknown { code, value } => {
                if value.len() > 255 {
                    return Err(CodecError::EncodingLimit);
                }
                (*code, value.clone())
            }
        };
        if caps.len() + value.len() + 2 > MAX_MESSAGE_LEN - 35 {
            return Err(CodecError::EncodingLimit);
        }
        caps.extend_from_slice(&[code, value.len() as u8]);
        caps.extend_from_slice(&value);
    }
    let mut body = vec![4];
    body.extend_from_slice(&my_as.to_be_bytes());
    body.extend_from_slice(&open.hold_time.to_be_bytes());
    body.extend_from_slice(&open.router_id.to_be_bytes());
    if caps.is_empty() {
        body.push(0);
    } else if caps.len() + 2 <= 255 {
        body.extend_from_slice(&[(caps.len() + 2) as u8, 2, caps.len() as u8]);
        body.extend_from_slice(&caps);
    } else {
        body.extend_from_slice(&[255, 255]);
        body.extend_from_slice(&((caps.len() + 3) as u16).to_be_bytes());
        body.push(2);
        body.extend_from_slice(&(caps.len() as u16).to_be_bytes());
        body.extend_from_slice(&caps);
    }
    Ok(body)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenCompatibilityError {
    #[error("four-octet ASN capability is required")]
    MissingFourOctetAsn,
    #[error("conflicting four-octet ASN capabilities")]
    ConflictingAsns,
    #[error("peer ASN mismatch: expected {expected:?}, observed {observed:?}")]
    AsnMismatch { expected: Asn, observed: Asn },
    #[error("peer is missing required family {0:?}")]
    MissingFamily(AddressFamily),
    #[error("invalid local OPEN requirements: {0}")]
    LocalRequirements(&'static str),
    #[error(transparent)]
    InvalidOpen(#[from] CodecError),
}

impl OpenCompatibilityError {
    /// Optional rejection for the future session owner; local errors never blame a peer.
    pub fn notification(&self, local: &OpenMessage) -> Option<NotificationMessage> {
        let (subcode, data) = match self {
            Self::AsnMismatch { .. } | Self::ConflictingAsns => (2, vec![]),
            Self::MissingFourOctetAsn => {
                let mut value = vec![65, 4];
                value.extend_from_slice(&local.effective_asn().ok()?.0.to_be_bytes());
                (7, value)
            }
            Self::MissingFamily(family) => {
                let afi: u16 = match family {
                    AddressFamily::Ipv4 => 1,
                    AddressFamily::Ipv6 => 2,
                };
                let [a, b] = afi.to_be_bytes();
                (7, vec![1, 4, a, b, 0, 1])
            }
            Self::InvalidOpen(error) => return error.notification(),
            Self::LocalRequirements(_) => return None,
        };
        Some(NotificationMessage {
            code: 2,
            subcode,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedOpen {
    pub peer_asn: Asn,
    pub hold_time: u16,
    pub families: BTreeSet<AddressFamily>,
}

/// Checks the fixture requirements without establishing a session or changing routes.
pub fn validate_open(
    local: &OpenMessage,
    remote: &OpenMessage,
    expected_asn: Asn,
    required: &[AddressFamily],
) -> Result<NegotiatedOpen, OpenCompatibilityError> {
    local
        .check_fields()
        .map_err(|_| OpenCompatibilityError::LocalRequirements("local OPEN fields are invalid"))?;
    remote.check_fields()?;
    local.effective_asn().map_err(|_| {
        OpenCompatibilityError::LocalRequirements("one consistent four-octet ASN is required")
    })?;
    let unique: BTreeSet<_> = required.iter().copied().collect();
    if unique.is_empty() || unique.len() != required.len() {
        return Err(OpenCompatibilityError::LocalRequirements(
            "required families must be nonempty and unique",
        ));
    }
    let peer_asn = remote.effective_asn()?;
    if peer_asn != expected_asn {
        return Err(OpenCompatibilityError::AsnMismatch {
            expected: expected_asn,
            observed: peer_asn,
        });
    }
    for family in &unique {
        let capability = Capability::unicast(*family);
        if !local.capabilities.contains(&capability) {
            return Err(OpenCompatibilityError::LocalRequirements(
                "local OPEN must advertise every required family",
            ));
        }
        if !remote.capabilities.contains(&capability) {
            return Err(OpenCompatibilityError::MissingFamily(*family));
        }
    }
    let families = [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .into_iter()
        .filter(|family| {
            local.capabilities.contains(&Capability::unicast(*family))
                && remote.capabilities.contains(&Capability::unicast(*family))
        })
        .collect();
    Ok(NegotiatedOpen {
        peer_asn,
        hold_time: local.hold_time.min(remote.hold_time),
        families,
    })
}
