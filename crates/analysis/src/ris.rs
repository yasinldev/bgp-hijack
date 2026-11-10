//! Filtered RIS Live observations. A bounded queue separates network reads from fsync.
use crate::{Error, Result, bundle::BundleWriter, model::*};
use bgp_hijack_core::{
    model::CanonicalPrefix,
    update::{Attributes, PathSegment},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};
#[derive(Clone)]
pub struct WatchOptions {
    pub prefixes: Vec<CanonicalPrefix>,
    pub collectors: Vec<String>,
    pub more_specific: bool,
    pub duration: Duration,
    pub output: PathBuf,
    pub limits: AnalysisLimits,
}
impl WatchOptions {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.prefixes.is_empty()
            || self.collectors.is_empty()
            || self.duration.is_zero()
            || self.duration > Duration::from_secs(86400)
            || self.prefixes.len() * self.collectors.len() > 128
            || self.collectors.iter().any(|c| {
                c.len() != 5 || !c.starts_with("rrc") || !c[3..].bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(Error::Invalid("watch requires prefixes, rrcNN collectors, <=128 subscriptions, and a duration of 1..86400 seconds".into()));
        }
        Ok(())
    }
    fn matches(&self, p: CanonicalPrefix) -> bool {
        self.prefixes.iter().any(|filter| {
            *filter == p
                || self.more_specific
                    && filter.family() == p.family()
                    && filter.network().prefix_len() < p.network().prefix_len()
                    && filter.network().contains(&p.network().addr())
        })
    }
}
fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error::Invalid(format!("RIS message missing {key}")))
}
fn asn(v: &Value) -> Result<u32> {
    v.as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| Error::Invalid("invalid RIS ASN".into()))
}
pub fn normalize(v: &Value, epoch: u64) -> Result<Vec<Observation>> {
    let kind = str_field(v, "type")?;
    if kind == "local_gap" {
        return Ok(vec![Observation::Gap {
            source: None,
            reason: str_field(v, "data")?.into(),
        }]);
    }
    if kind == "ris_subscribe_ok" {
        return Ok(vec![Observation::SourceStatus {
            source: Source {
                source: "ris_live".into(),
                collector: v["data"]["subscription"]["host"]
                    .as_str()
                    .map(str::to_owned),
                peer: "subscription".into(),
                epoch,
            },
            status: "subscribed".into(),
        }]);
    }
    if kind != "ris_message" {
        return Ok(vec![]);
    }
    let d = &v["data"];
    let host = str_field(d, "host")?;
    if host.len() != 5 || !host.starts_with("rrc") || !host[3..].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Invalid("invalid RIS collector identity".into()));
    }
    if d.get("raw")
        .and_then(Value::as_str)
        .is_some_and(|raw| raw.len() > 8192)
    {
        return Err(Error::Limit(
            "RIS extended BGP messages are unsupported".into(),
        ));
    }
    let peer = str_field(d, "peer")?;
    let peer_asn = str_field(d, "peer_asn")?;
    peer.parse::<std::net::IpAddr>()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    peer_asn
        .parse::<u32>()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let source = Source {
        source: "ris_live".into(),
        collector: Some(host.into()),
        peer: format!("{peer} AS{peer_asn}"),
        epoch,
    };
    let time = d["timestamp"]
        .as_f64()
        .filter(|t| t.is_finite())
        .ok_or_else(|| Error::Invalid("invalid RIS timestamp".into()))?;
    match str_field(d, "type")? {
        "RIS_PEER_STATE" => {
            return Ok(vec![Observation::SourceStatus {
                source,
                status: match str_field(d, "state")? {
                    "up" => "up",
                    "connected" => "reconnect",
                    "down" => "down",
                    _ => return Err(Error::Invalid("invalid RIS peer state".into())),
                }
                .into(),
            }]);
        }
        "NOTIFICATION" => {
            return Ok(vec![Observation::SourceStatus {
                source,
                status: "notification".into(),
            }]);
        }
        "UPDATE" => {}
        _ => return Ok(vec![]),
    }
    let mut attributes = Attributes::default();
    if let Some(path) = d.get("path") {
        for segment in path
            .as_array()
            .ok_or_else(|| Error::Invalid("invalid RIS path".into()))?
        {
            if let Some(set) = segment.as_array() {
                if set.is_empty() {
                    return Err(Error::Invalid("empty RIS AS_SET".into()));
                }
                attributes.path.push(PathSegment {
                    kind: 1,
                    asns: set.iter().map(asn).collect::<Result<_>>()?,
                });
            } else {
                let n = asn(segment)?;
                if let Some(last) = attributes.path.last_mut().filter(|s| s.kind == 2) {
                    last.asns.push(n);
                } else {
                    attributes.path.push(PathSegment {
                        kind: 2,
                        asns: vec![n],
                    });
                }
            }
        }
    }
    attributes.origin = match d.get("origin").and_then(Value::as_str) {
        Some("igp") => Some(0),
        Some("egp") => Some(1),
        Some("incomplete") => Some(2),
        Some(_) => return Err(Error::Invalid("invalid RIS origin".into())),
        None => None,
    };
    let path_asns = attributes.path.iter().map(|s| s.asns.len()).sum::<usize>();
    let route_count = d
        .get("withdrawals")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
        .saturating_add(
            d.get("announcements")
                .and_then(Value::as_array)
                .map_or(0, |groups| {
                    groups
                        .iter()
                        .map(|g| {
                            g.get("prefixes")
                                .and_then(Value::as_array)
                                .map_or(0, Vec::len)
                        })
                        .sum::<usize>()
                }),
        );
    let per_route = 512usize
        .saturating_add(
            attributes
                .path
                .len()
                .saturating_mul(std::mem::size_of::<PathSegment>()),
        )
        .saturating_add(path_asns.saturating_mul(4));
    if path_asns > 2048
        || route_count > 4096
        || route_count.saturating_mul(per_route) > 8 * 1024 * 1024
    {
        return Err(Error::Limit("RIS normalization expansion budget".into()));
    }
    let mut out = Vec::new();
    if let Some(withdrawals) = d.get("withdrawals") {
        for p in withdrawals
            .as_array()
            .ok_or_else(|| Error::Invalid("invalid RIS withdrawals".into()))?
        {
            let prefix: CanonicalPrefix = p
                .as_str()
                .ok_or_else(|| Error::Invalid("invalid RIS prefix".into()))?
                .parse()
                .map_err(|e| Error::Invalid(format!("{e}")))?;
            out.push(Observation::Route(RouteObservation {
                source: source.clone(),
                source_time: Some(time),
                prefix,
                address_family: prefix.family(),
                path_id: None,
                action: RouteAction::Withdraw,
                attributes: Attributes::default(),
            }));
        }
    }
    if let Some(announcements) = d.get("announcements") {
        for a in announcements
            .as_array()
            .ok_or_else(|| Error::Invalid("invalid RIS announcements".into()))?
        {
            if d.get("path").is_none() {
                return Err(Error::Invalid("RIS announcement missing path".into()));
            }
            let mut attrs = attributes.clone();
            let hop = str_field(a, "next_hop")?;
            hop.parse::<std::net::IpAddr>()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            attrs.next_hops = vec![hop.into()];
            for p in a["prefixes"]
                .as_array()
                .ok_or_else(|| Error::Invalid("missing RIS prefixes".into()))?
            {
                let prefix: CanonicalPrefix = p
                    .as_str()
                    .ok_or_else(|| Error::Invalid("invalid RIS prefix".into()))?
                    .parse()
                    .map_err(|e| Error::Invalid(format!("{e}")))?;
                out.push(Observation::Route(RouteObservation {
                    source: source.clone(),
                    source_time: Some(time),
                    prefix,
                    address_family: prefix.family(),
                    path_id: None,
                    action: RouteAction::Announce,
                    attributes: attrs.clone(),
                }));
            }
        }
    }
    Ok(out)
}
enum Item {
    Data {
        raw: String,
        epoch: u64,
        _permit: OwnedSemaphorePermit,
    },
    End {
        complete: bool,
        reason: Option<String>,
    },
}
struct QueueBudget {
    slots: Arc<Semaphore>,
    limit: usize,
    peak: AtomicUsize,
}
fn enqueue(
    tx: &mpsc::Sender<Item>,
    budget: &Arc<QueueBudget>,
    raw: String,
    epoch: u64,
) -> Result<()> {
    let permit = budget
        .slots
        .clone()
        .try_acquire_many_owned(
            u32::try_from(raw.len().max(1)).map_err(|_| Error::Limit("RIS message size".into()))?,
        )
        .map_err(|_| Error::Limit("RIS queue byte budget".into()))?;
    budget.peak.fetch_max(
        budget.limit - budget.slots.available_permits(),
        Ordering::Relaxed,
    );
    tx.try_send(Item::Data {
        raw,
        epoch,
        _permit: permit,
    })
    .map_err(|_| Error::Limit("RIS queue saturated or writer unavailable".into()))
}
async fn collect(
    url: &str,
    options: &WatchOptions,
    tx: &mpsc::Sender<Item>,
    budget: &Arc<QueueBudget>,
    ready: &AtomicBool,
) -> Result<()> {
    for epoch in 1..=6 {
        ready.store(false, Ordering::SeqCst);
        if epoch > 1 {
            enqueue(tx,budget,json!({"type":"local_gap","data":"RIS connection lost; comparison baseline invalidated"}).to_string(),epoch)?;
            tokio::time::sleep(Duration::from_secs(1 << (epoch - 2))).await;
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(options.limits.record_bytes))
            .max_frame_size(Some(options.limits.record_bytes));
        let connection = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_tungstenite::connect_async_with_config(url, Some(config), false),
        )
        .await;
        let Ok(Ok((mut socket, _))) = connection else {
            continue;
        };
        let mut pending = BTreeSet::new();
        for host in &options.collectors {
            for prefix in &options.prefixes {
                let sub = json!({"host":host,"prefix":prefix.to_string(),"moreSpecific":options.more_specific,"lessSpecific":false,"socketOptions":{"acknowledge":true,"includeRaw":true}});
                pending.insert((host.clone(), prefix.to_string()));
                socket
                    .send(Message::Text(
                        json!({"type":"ris_subscribe","data":sub})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .map_err(|e| Error::Provider(e.to_string()))?;
            }
        }
        let ack_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
        let mut last = tokio::time::Instant::now();
        let mut ids = BTreeSet::new();
        let mut order = VecDeque::new();
        loop {
            tokio::select! {
                _=tokio::time::sleep_until(ack_deadline),if !pending.is_empty()=>return Err(Error::Provider("RIS subscription acknowledgement timeout".into())),
                _=heartbeat.tick()=>{if last.elapsed()>Duration::from_secs(45){break;}
                    if socket.send(Message::Text(json!({"type":"ping"}).to_string().into())).await.is_err(){break;}},
                message=socket.next()=>{
                    let Some(Ok(message))=message else{break;};last=tokio::time::Instant::now();
                    match message {
                        Message::Text(raw)=>{
                            let value:Value=serde_json::from_str(&raw)?;
                            match value["type"].as_str(){
                                Some("ris_error")=>return Err(Error::Provider(format!("RIS rejected request: {}",value["data"]))),
                                Some("ris_subscribe_ok")=>{let sub=&value["data"]["subscription"];if let (Some(h),Some(p))=(sub["host"].as_str(),sub["prefix"].as_str()){pending.remove(&(h.into(),p.into()));ready.store(pending.is_empty(),Ordering::SeqCst);}},
                                Some("pong")=>continue,
                                Some("ping")=>{socket.send(Message::Text(json!({"type":"ping"}).to_string().into())).await.map_err(|e|Error::Provider(e.to_string()))?;continue;},
                                _=>{}
                            }
                            if let Some(id)=value["data"]["id"].as_str() {if id.len()>256{return Err(Error::Provider("RIS message id exceeds 256 bytes".into()));}
                                if !ids.insert(id.to_owned()){continue;}order.push_back(id.to_owned());if order.len()>65536 {ids.remove(&order.pop_front().expect("queued id"));}}
                            enqueue(tx,budget,raw.to_string(),epoch)?;
                        },Message::Ping(p)=>{if socket.send(Message::Pong(p)).await.is_err(){break;}},Message::Close(_)=>break,_=>{}
                    }
                }
            }
        }
    }
    Err(Error::Provider("RIS reconnect budget exhausted".into()))
}
pub async fn watch(options: WatchOptions) -> Result<(AnalysisSummary, u8)> {
    watch_url(options, "wss://ris-live.ripe.net/v1/ws/?client=bgp-hijack").await
}
pub async fn watch_url(options: WatchOptions, url: &str) -> Result<(AnalysisSummary, u8)> {
    options.validate()?;
    let writer = BundleWriter::create(
        &options.output,
        "RIS Live".into(),
        json!({"prefixes":options.prefixes,"collectors":options.collectors,"more_specific":options.more_specific,"duration_seconds":options.duration.as_secs(),"initial_rib":false}),
        options.limits.clone(),
    )?;
    let (tx, mut rx) = mpsc::channel(256);
    let budget = Arc::new(QueueBudget {
        slots: Arc::new(Semaphore::new(options.limits.queue_bytes)),
        limit: options.limits.queue_bytes,
        peak: AtomicUsize::new(0),
    });
    let worker_budget = budget.clone();
    let worker_options = options.clone();
    let mut worker =
        tokio::task::spawn_blocking(move || -> Result<AnalysisSummary> {
            let mut writer = writer;
            let mut peer_epochs: BTreeMap<(u64, String, String), u64> = BTreeMap::new();
            while let Some(item) = rx.blocking_recv() {
                match item {
                    Item::Data {
                        raw,
                        epoch,
                        _permit,
                    } => {
                        let reference = writer.evidence(raw.as_bytes())?;
                        let value: Value = serde_json::from_str(&raw)?;
                        match normalize(&value, epoch) {
                            Ok(events) => {
                                for mut event in events {
                                    let src = match &mut event {
                                        Observation::Route(r) => Some(&mut r.source),
                                        Observation::SourceStatus { source, .. } => Some(source),
                                        Observation::Gap { source, .. } => source.as_mut(),
                                    };
                                    if let Some(src) = src {
                                        let key = (
                                            epoch,
                                            src.collector.clone().unwrap_or_default(),
                                            src.peer.clone(),
                                        );
                                        if peer_epochs.len() >= worker_options.limits.routes
                                            && !peer_epochs.contains_key(&key)
                                        {
                                            return Err(Error::Limit("RIS peer epochs".into()));
                                        }
                                        let local = peer_epochs.entry(key).or_default();
                                        src.epoch = epoch * 1_000_000 + *local;
                                    }
                                    if let Observation::SourceStatus { source, status } = &mut event
                                        && matches!(
                                            status.as_str(),
                                            "down" | "reconnect" | "notification"
                                        )
                                    {
                                        let key = (
                                            epoch,
                                            source.collector.clone().unwrap_or_default(),
                                            source.peer.clone(),
                                        );
                                        let local = peer_epochs.entry(key).or_default();
                                        *local += 1;
                                        source.epoch = epoch * 1_000_000 + *local;
                                    }
                                    if let Observation::Route(r) = &event
                                        && (!worker_options.matches(r.prefix)
                                            || !r.source.collector.as_ref().is_some_and(|c| {
                                                worker_options.collectors.contains(c)
                                            }))
                                    {
                                        continue;
                                    }
                                    writer.record(event, vec![reference.clone()])?;
                                }
                            }
                            Err(e) => writer.gap(e.to_string())?,
                        }
                    }
                    Item::End { complete, reason } => {
                        if let Some(reason) = reason {
                            writer.gap(reason)?;
                        }
                        writer.metric(
                            "queue_peak_bytes",
                            worker_budget.peak.load(Ordering::Relaxed) as f64,
                        );
                        return writer.finish(complete);
                    }
                }
            }
            writer.finish(false)
        });
    let ready = AtomicBool::new(false);
    let (complete, code, reason) = tokio::select! {
        result=&mut worker=>{let summary=result.map_err(|e|Error::Invalid(e.to_string()))??;return Ok((summary,3));},
        r=collect(url,&options,&tx,&budget,&ready)=>match r {Ok(())=>(true,0,None),Err(e)=>(false,3,Some(e.to_string()))},
        _=tokio::time::sleep(options.duration)=>if ready.load(Ordering::SeqCst){(true,0,None)}else{(false,4,Some("recording ended without all subscriptions acknowledged".into()))},
        _=tokio::signal::ctrl_c()=>(false,130,Some("watch interrupted by user".into())),
    };
    let _ = tx.send(Item::End { complete, reason }).await;
    drop(tx);
    let summary = worker
        .await
        .map_err(|e| Error::Invalid(format!("analysis writer task: {e}")))??;
    let code = if code == 0 && summary.coverage == "partial" {
        4
    } else {
        code
    };
    Ok((summary, code))
}
