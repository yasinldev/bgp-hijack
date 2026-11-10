//! Source-local evidence state. Gaps invalidate comparisons rather than implying withdrawal.
use crate::{Error, Result, model::*};
use bgp_hijack_core::model::CanonicalPrefix;
use std::collections::BTreeMap;
type Key = (Source, CanonicalPrefix, Option<u32>);
#[derive(Clone)]
struct Route {
    value: RouteObservation,
    sequence: u64,
}
pub struct Analyzer {
    epochs: BTreeMap<(String, Option<String>, String), u64>,
    routes: BTreeMap<Key, Route>,
    latest: BTreeMap<Source, f64>,
    pub findings: Vec<Finding>,
    pub gaps: Vec<String>,
    limits: AnalysisLimits,
    pub events: u64,
}
impl Analyzer {
    pub fn new(limits: AnalysisLimits) -> Self {
        Self {
            epochs: BTreeMap::new(),
            routes: BTreeMap::new(),
            latest: BTreeMap::new(),
            findings: Vec::new(),
            gaps: Vec::new(),
            limits,
            events: 0,
        }
    }
    pub fn snapshot(&self) -> Vec<RouteObservation> {
        self.routes.values().map(|r| r.value.clone()).collect()
    }
    pub fn invalidate(&mut self, source: Option<&Source>) {
        if let Some(s) = source {
            self.routes.retain(|(k, _, _), _| {
                k.source != s.source || k.collector != s.collector || k.peer != s.peer
            });
            self.latest.retain(|k, _| {
                k.source != s.source || k.collector != s.collector || k.peer != s.peer
            });
        } else {
            self.routes.clear();
            self.latest.clear();
        }
    }
    pub fn apply(&mut self, event: &AnalysisEvent) -> Result<()> {
        self.events += 1;
        let r = match &event.observation {
            Observation::Gap { source, reason } => {
                self.invalidate(source.as_ref());
                if self.gaps.len() < 1024 {
                    self.gaps.push(reason.clone());
                }
                return Ok(());
            }
            Observation::SourceStatus { source, status } => {
                if matches!(
                    status.as_str(),
                    "down" | "notification" | "reconnect" | "replaced"
                ) {
                    self.invalidate(Some(source));
                }
                return Ok(());
            }
            Observation::Route(r) => r,
        };
        if r.address_family != r.prefix.family() {
            return Err(Error::Invalid(
                "route address family differs from prefix".into(),
            ));
        }
        let identity = (
            r.source.source.clone(),
            r.source.collector.clone(),
            r.source.peer.clone(),
        );
        if self
            .epochs
            .get(&identity)
            .is_some_and(|epoch| *epoch > r.source.epoch)
        {
            if self.gaps.len() < 1024 {
                self.gaps.push("stale session epoch ignored".into());
            }
            return Ok(());
        }
        if !self.epochs.contains_key(&identity) && self.epochs.len() >= self.limits.routes {
            return Err(Error::Limit("source identity count".into()));
        }
        self.epochs.insert(identity, r.source.epoch);
        if event.evidence_refs.is_empty() {
            self.invalidate(Some(&r.source));
            self.gaps.push("route without evidence".into());
            return Ok(());
        }
        if let Some(t) = r.source_time {
            if !t.is_finite() {
                return Err(Error::Invalid("non-finite source time".into()));
            }
            if self.latest.get(&r.source).is_some_and(|old| *old > t) {
                self.invalidate(Some(&r.source));
                if self.gaps.len() < 1024 {
                    self.gaps
                        .push("out-of-order source time invalidated baseline".into());
                }
                return Ok(());
            }
            self.latest.insert(r.source.clone(), t);
        }
        // A new epoch replaces only this source/collector/peer's prior state.
        self.routes.retain(|(s, _, _), _| {
            !(s.source == r.source.source
                && s.collector == r.source.collector
                && s.peer == r.source.peer
                && s.epoch != r.source.epoch)
        });
        let key = (r.source.clone(), r.prefix, r.path_id);
        if r.action == RouteAction::Withdraw {
            self.routes.remove(&key);
            return Ok(());
        }
        let mut changes = Vec::new();
        if let Some(old) = self.routes.get(&key) {
            if old.value.attributes.path != r.attributes.path {
                if old
                    .value
                    .attributes
                    .origin_asn()
                    .zip(r.attributes.origin_asn())
                    .is_some_and(|(a, b)| a != b)
                {
                    changes.push((
                        FindingKind::OriginChanged,
                        old.clone(),
                        "Origin changed within one continuous peer observation period",
                    ));
                }
                changes.push((
                    FindingKind::AsPathChanged,
                    old.clone(),
                    "AS path segments or prepends changed",
                ));
            }
        } else {
            // More-specific evidence must coexist in the same peer's continuous period.
            if let Some(old) = self
                .routes
                .values()
                .filter(|old| {
                    old.value.source == r.source
                        && old.value.prefix.family() == r.prefix.family()
                        && old.value.prefix.network().prefix_len() < r.prefix.network().prefix_len()
                        && old
                            .value
                            .prefix
                            .network()
                            .contains(&r.prefix.network().addr())
                })
                .max_by_key(|old| old.value.prefix.network().prefix_len())
            {
                changes.push((
                    FindingKind::MoreSpecificObserved,
                    old.clone(),
                    "More-specific prefix coexists with a covering route",
                ));
            }
        }
        let changed_origin = self
            .routes
            .get(&key)
            .is_none_or(|old| old.value.attributes.origin_asn() != r.attributes.origin_asn());
        if changed_origin && let Some(origin) = r.attributes.origin_asn() {
            // Do not merge unrelated files or collectors. Within a collector, observations
            // must carry comparable source timestamps, within a bounded 5-minute window.
            if let Some(old) = self.routes.values().find(|old| {
                old.value.prefix == r.prefix
                    && !(old.value.source == r.source && old.value.path_id == r.path_id)
                    && old.value.source.source == r.source.source
                    && old.value.source.collector == r.source.collector
                    && old.value.source.epoch == r.source.epoch
                    && old
                        .value
                        .attributes
                        .origin_asn()
                        .is_some_and(|v| v != origin)
                    && old
                        .value
                        .source_time
                        .zip(r.source_time)
                        .is_some_and(|(a, b)| (a - b).abs() <= 300.0)
            }) {
                changes.push((
                    FindingKind::MultipleOriginsObserved,
                    old.clone(),
                    "Different origins observed concurrently within this source/collector window",
                ));
            }
        }
        if self.findings.len() + changes.len() > self.limits.findings {
            return Err(Error::Limit("finding count".into()));
        }
        for (kind, old, explanation) in changes {
            self.findings.push(Finding {
                rule_version: 1,
                kind,
                prefix: r.prefix,
                sources: vec![old.value.source, r.source.clone()],
                observations: vec![old.sequence, event.sequence],
                explanation: explanation.into(),
            });
        }
        if !self.routes.contains_key(&key) && self.routes.len() >= self.limits.routes {
            return Err(Error::Limit("route count".into()));
        }
        self.routes.insert(
            key,
            Route {
                value: r.clone(),
                sequence: event.sequence,
            },
        );
        Ok(())
    }
    pub fn summary(&self, id: &str, complete: bool) -> AnalysisSummary {
        AnalysisSummary {
            schema_version: 1,
            run_id: id.into(),
            processing_status: if complete { "completed" } else { "interrupted" }.into(),
            coverage: if complete && self.gaps.is_empty() {
                "selected_input"
            } else {
                "partial"
            }
            .into(),
            events: self.events,
            routes: self.routes.len(),
            gaps: self.gaps.clone(),
            findings: self.findings.clone(),
            metrics: BTreeMap::new(),
        }
    }
}
