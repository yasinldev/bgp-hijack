//! Bounded RIPEstat requests; provider time and visibility metadata remain intact.
use crate::{Error, Result, bundle::now};
use bgp_hijack_core::model::CanonicalPrefix;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::IpAddr, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[derive(Debug, Clone)]
pub enum Query {
    Ip(IpAddr),
    Prefix(CanonicalPrefix),
    Asn {
        asn: u32,
        start: Option<String>,
        end: Option<String>,
    },
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LookupResult {
    pub schema_version: u32,
    pub provider: String,
    pub retrieved_at: String,
    pub query: String,
    pub status: String,
    pub responses: Value,
}
pub struct LookupClient {
    client: reqwest::Client,
    base: String,
    pub max_bytes: usize,
    pub timeout: Duration,
    pub attempts: usize,
}
impl LookupClient {
    pub fn new() -> Result<Self> {
        Self::with_base("https://stat.ripe.net")
    }
    /// An explicit base is useful for local mock servers. The CLI uses the official HTTPS origin.
    pub fn with_base(base: &str) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .user_agent("bgp-hijack/0.1 passive-analysis")
                .build()
                .map_err(|e| Error::Provider(e.to_string()))?,
            base: base.trim_end_matches('/').into(),
            max_bytes: 4 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            attempts: 3,
        })
    }
    async fn request(&self, endpoint: &str, params: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}/data/{endpoint}/data.json", self.base);
        for attempt in 0..self.attempts {
            let response = self
                .client
                .get(&url)
                .query(params)
                .timeout(self.timeout)
                .send()
                .await;
            let mut response = match response {
                Ok(r) => r,
                Err(e) => {
                    if attempt + 1 < self.attempts {
                        tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                        continue;
                    }
                    return Err(Error::Provider(e.to_string()));
                }
            };
            if (response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                || response.status().is_server_error())
                && attempt + 1 < self.attempts
            {
                let delay = response
                    .headers()
                    .get("retry-after")
                    .and_then(|s| s.to_str().ok())
                    .and_then(retry_delay)
                    .unwrap_or(Duration::from_secs(1 << attempt));
                if delay > Duration::from_secs(30) {
                    return Err(Error::Provider(
                        "Retry-After exceeds the bounded retry budget".into(),
                    ));
                }
                tokio::time::sleep(delay).await;
                continue;
            }
            if !response.status().is_success() {
                return Err(Error::Provider(format!(
                    "{endpoint}: HTTP {}",
                    response.status()
                )));
            }
            let mut bytes = Vec::new();
            while let Some(b) = response
                .chunk()
                .await
                .map_err(|e| Error::Provider(e.to_string()))?
            {
                if bytes.len() + b.len() > self.max_bytes {
                    return Err(Error::Limit("RIPEstat response".into()));
                }
                bytes.extend_from_slice(&b);
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            if value.get("status").and_then(Value::as_str) != Some("ok")
                || !value.get("data").is_some_and(Value::is_object)
            {
                return Err(Error::Provider(format!(
                    "{endpoint}: invalid API response envelope"
                )));
            }
            return Ok(value);
        }
        Err(Error::Provider("request retry budget exhausted".into()))
    }
    pub async fn lookup(&self, q: Query) -> Result<LookupResult> {
        let (query, responses, has_data) = match q {
            Query::Ip(ip) => {
                let r = self
                    .request("network-info", &[("resource", ip.to_string())])
                    .await?;
                let found = r["data"]["prefix"].as_str().is_some_and(|s| !s.is_empty());
                (ip.to_string(), json!({"network_info":r}), found)
            }
            Query::Prefix(p) => {
                let r = self
                    .request("prefix-overview", &[("resource", p.to_string())])
                    .await?;
                let found = r["data"]["announced"].as_bool().unwrap_or(false);
                (p.to_string(), json!({"prefix_overview":r}), found)
            }
            Query::Asn { asn, start, end } => {
                let end = end
                    .map(|s| {
                        OffsetDateTime::parse(&s, &Rfc3339)
                            .map_err(|_| Error::Invalid("end must be an RFC3339 timestamp".into()))
                    })
                    .transpose()?
                    .unwrap_or_else(OffsetDateTime::now_utc);
                let start = start
                    .map(|s| {
                        OffsetDateTime::parse(&s, &Rfc3339).map_err(|_| {
                            Error::Invalid("start must be an RFC3339 timestamp".into())
                        })
                    })
                    .transpose()?
                    .unwrap_or(end - time::Duration::hours(24));
                if start >= end {
                    return Err(Error::Invalid("start must precede end".into()));
                }
                let resource = format!("AS{asn}");
                let overview = self
                    .request("as-overview", &[("resource", resource.clone())])
                    .await?;
                let prefixes = self
                    .request(
                        "announced-prefixes",
                        &[
                            ("resource", resource.clone()),
                            ("starttime", start.unix_timestamp().to_string()),
                            ("endtime", end.unix_timestamp().to_string()),
                        ],
                    )
                    .await?;
                let found = prefixes["data"]["prefixes"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty());
                (
                    resource,
                    json!({"as_overview":overview,"announced_prefixes":prefixes}),
                    found,
                )
            }
        };
        Ok(LookupResult {
            schema_version: 1,
            provider: "RIPEstat".into(),
            retrieved_at: now(),
            query,
            status: if has_data { "observed" } else { "no_data" }.into(),
            responses,
        })
    }
}
fn retry_delay(value: &str) -> Option<Duration> {
    value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value).ok().map(|t| {
                t.duration_since(std::time::SystemTime::now())
                    .unwrap_or_default()
            })
        })
}
