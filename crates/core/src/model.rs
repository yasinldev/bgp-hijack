use std::{fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::ModelError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CanonicalPrefix(IpNet);

impl CanonicalPrefix {
    pub fn family(self) -> AddressFamily {
        AddressFamily::of(self.0.addr())
    }

    pub fn network(self) -> IpNet {
        self.0
    }

    pub fn is_documentation(self) -> bool {
        match self.0 {
            IpNet::V4(net) => {
                net.prefix_len() >= 24 && is_documentation_address(IpAddr::V4(net.addr()))
            }
            IpNet::V6(net) => {
                net.prefix_len() >= 32 && is_documentation_address(IpAddr::V6(net.addr()))
            }
        }
    }
}

impl FromStr for CanonicalPrefix {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let network = value.parse::<IpNet>().map_err(|error| ModelError::Prefix {
            value: value.into(),
            reason: error.to_string(),
        })?;
        if network != network.trunc() {
            return Err(ModelError::Prefix {
                value: value.into(),
                reason: "host bits must be zero; provide the canonical network prefix".into(),
            });
        }
        Ok(Self(network))
    }
}

impl TryFrom<String> for CanonicalPrefix {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<CanonicalPrefix> for String {
    fn from(value: CanonicalPrefix) -> Self {
        value.to_string()
    }
}

impl fmt::Display for CanonicalPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Documentation-space membership is a static constraint, not proof of isolation.
pub fn is_documentation_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let bytes = address.octets();
            matches!(&bytes[..3], [192, 0, 2] | [198, 51, 100] | [203, 0, 113])
        }
        IpAddr::V6(address) => address.segments()[..2] == [0x2001, 0x0db8],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Asn(pub u32);

impl Asn {
    pub fn is_private(self) -> bool {
        matches!(self.0, 64512..=65534 | 4_200_000_000..=4_294_967_294)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PeerId(String);

impl PeerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PeerId {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !is_identifier(&value) {
            return Err(ModelError::PeerId(value));
        }
        Ok(Self(value))
    }
}

impl From<PeerId> for String {
    fn from(value: PeerId) -> Self {
        value.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionEpoch(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Forward,
    Blackhole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Completed,
    Failed,
    Unverified,
}
