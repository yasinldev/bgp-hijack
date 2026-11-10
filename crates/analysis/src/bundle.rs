use crate::{Error, Result, model::*, state::Analyzer};
use bgp_hijack_core::storage::persist;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp")
}
pub fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut data = Vec::new();
    f.take(
        max.checked_add(1)
            .ok_or_else(|| Error::Limit("read size overflow".into()))?,
    )
    .read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(Error::Limit(format!(
            "{} exceeds {max} bytes",
            path.display()
        )));
    }
    Ok(data)
}
fn artifact(path: &Path, max: u64) -> Result<Artifact> {
    let mut reader = File::open(path)?;
    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > max {
            return Err(Error::Limit("artifact size".into()));
        }
        digest.update(&buffer[..n]);
    }
    Ok(Artifact {
        size_bytes: count,
        sha256: format!("{:x}", digest.finalize()),
    })
}
fn new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    persist(&mut f, bytes)?;
    Ok(())
}
fn write_manifest(dir: &Path, m: &AnalysisManifest) -> Result<()> {
    let data = serde_json::to_vec_pretty(m)?;
    if data.len() > 4 * 1024 * 1024 {
        return Err(Error::Limit("manifest size".into()));
    }
    let temp = dir.join("manifest.next");
    new_file(&temp, &data)?;
    fs::rename(temp, dir.join("manifest.json"))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
pub struct BundleWriter {
    dir: PathBuf,
    manifest: AnalysisManifest,
    journal: File,
    start: Instant,
    sequence: u64,
    bytes: u64,
    journal_bytes: u64,
    failed: bool,
    analyzer: Analyzer,
    sync_ms: f64,
    max_sync_ms: f64,
    extra_metrics: BTreeMap<String, f64>,
    cancellation: Arc<AtomicBool>,
}
impl BundleWriter {
    pub fn create(
        dir: &Path,
        input: String,
        filters: serde_json::Value,
        limits: AnalysisLimits,
    ) -> Result<Self> {
        limits.validate()?;
        fs::create_dir(dir)?;
        fs::create_dir(dir.join("evidence"))?;
        let started_at = now();
        let run_id = format!(
            "{}-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos(),
            std::process::id()
        );
        let manifest = AnalysisManifest {
            schema_version: 1,
            kind: "passive_analysis".into(),
            run_id,
            started_at,
            input,
            filters,
            software_version: env!("CARGO_PKG_VERSION").into(),
            limits: limits.clone(),
            complete: false,
            artifacts: BTreeMap::new(),
        };
        write_manifest(dir, &manifest)?;
        let journal = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join("events.jsonl"))?;
        journal.sync_all()?;
        File::open(dir)?.sync_all()?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            dir: dir.into(),
            manifest,
            journal,
            start: Instant::now(),
            sequence: 0,
            bytes: 0,
            journal_bytes: 0,
            failed: false,
            analyzer: Analyzer::new(limits),
            sync_ms: 0.0,
            max_sync_ms: 0.0,
            extra_metrics: BTreeMap::new(),
            cancellation: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancellation.clone()
    }
    pub fn check_cancelled(&self) -> Result<()> {
        if self.cancellation.load(Ordering::Relaxed) {
            Err(Error::Interrupted)
        } else {
            Ok(())
        }
    }
    pub fn metric(&mut self, name: &str, value: f64) {
        if value.is_finite() {
            self.extra_metrics.insert(name.into(), value);
        }
    }
    pub fn limits(&self) -> &AnalysisLimits {
        &self.manifest.limits
    }
    pub fn evidence(&mut self, data: &[u8]) -> Result<String> {
        if self.failed {
            return Err(Error::Invalid(
                "analysis writer is unusable after I/O failure".into(),
            ));
        }
        if data.len() > self.manifest.limits.record_bytes {
            return Err(Error::Limit("evidence record".into()));
        }
        let digest = hash(data);
        let name = format!("evidence/{digest}.bin");
        if !self.manifest.artifacts.contains_key(&name) {
            if self.bytes + data.len() as u64 > self.manifest.limits.output_bytes
                || self.manifest.artifacts.len() >= 10_000
            {
                return Err(Error::Limit("bundle evidence budget".into()));
            }
            if let Err(e) = new_file(&self.dir.join(&name), data)
                .and_then(|()| Ok(File::open(self.dir.join("evidence"))?.sync_all()?))
            {
                self.failed = true;
                return Err(e);
            }
            self.bytes += data.len() as u64;
            self.manifest.artifacts.insert(
                name.clone(),
                Artifact {
                    size_bytes: data.len() as u64,
                    sha256: digest,
                },
            );
        }
        Ok(name)
    }
    pub fn record(&mut self, observation: Observation, evidence_refs: Vec<String>) -> Result<()> {
        if self.failed {
            return Err(Error::Invalid(
                "analysis writer is unusable after I/O failure".into(),
            ));
        }
        let e = AnalysisEvent {
            schema_version: 1,
            run_id: self.manifest.run_id.clone(),
            sequence: self.sequence + 1,
            received_at: now(),
            elapsed_ms: self.start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            evidence_refs,
            observation,
        };
        let mut bytes = serde_json::to_vec(&e)?;
        bytes.push(b'\n');
        // Reserve space for one terminal gap.
        let reserve = if matches!(e.observation, Observation::Gap { .. }) {
            0
        } else {
            4096
        };
        if bytes.len() > self.manifest.limits.record_bytes
            || self.journal_bytes + bytes.len() as u64 + reserve
                > self.manifest.limits.journal_bytes
            || self.bytes + bytes.len() as u64 + reserve > self.manifest.limits.output_bytes
        {
            return Err(Error::Limit("analysis journal budget".into()));
        }
        let begin = Instant::now();
        if let Err(e) = persist(&mut self.journal, &bytes) {
            self.failed = true;
            return Err(e.into());
        }
        let latency = begin.elapsed().as_secs_f64() * 1000.0;
        self.sync_ms += latency;
        self.max_sync_ms = self.max_sync_ms.max(latency);
        self.bytes += bytes.len() as u64;
        self.journal_bytes += bytes.len() as u64;
        self.sequence += 1;
        self.analyzer.apply(&e)
    }
    pub fn gap(&mut self, reason: impl Into<String>) -> Result<()> {
        self.record(
            Observation::Gap {
                source: None,
                reason: reason.into(),
            },
            vec![],
        )
    }
    pub fn finish(mut self, complete: bool) -> Result<AnalysisSummary> {
        if self.failed {
            return Err(Error::Invalid("cannot finalize failed writer".into()));
        }
        let mut summary = self.analyzer.summary(&self.manifest.run_id, complete);
        summary.metrics.extend(self.extra_metrics.clone());
        summary
            .metrics
            .insert("max_durable_write_ms".into(), self.max_sync_ms);
        summary.metrics.insert(
            "duration_seconds".into(),
            self.start.elapsed().as_secs_f64(),
        );
        summary
            .metrics
            .insert("durable_write_ms".into(), self.sync_ms);
        summary
            .metrics
            .insert("output_bytes".into(), self.bytes as f64);
        summary.metrics.insert(
            "events_per_second".into(),
            self.sequence as f64 / self.start.elapsed().as_secs_f64().max(0.000001),
        );
        self.manifest.artifacts.insert(
            "events.jsonl".into(),
            artifact(
                &self.dir.join("events.jsonl"),
                self.manifest.limits.journal_bytes,
            )?,
        );
        for (name, data) in [
            ("summary.json", serde_json::to_vec_pretty(&summary)?),
            (
                "findings.jsonl",
                self.analyzer
                    .findings
                    .iter()
                    .map(|f| serde_json::to_string(f).map(|s| s + "\n"))
                    .collect::<std::result::Result<String, _>>()?
                    .into_bytes(),
            ),
        ] {
            if self.bytes + data.len() as u64 > self.manifest.limits.output_bytes {
                return Err(Error::Limit("bundle summary budget".into()));
            }
            new_file(&self.dir.join(name), &data)?;
            self.bytes += data.len() as u64;
            self.manifest.artifacts.insert(
                name.into(),
                Artifact {
                    size_bytes: data.len() as u64,
                    sha256: hash(&data),
                },
            );
        }
        self.manifest.complete = complete;
        write_manifest(&self.dir, &self.manifest)?;
        Ok(summary)
    }
}
/// Replays evidence, never trusts the saved summary or executes network requests.
pub fn report(dir: &Path) -> Result<AnalysisSummary> {
    let m: AnalysisManifest =
        serde_json::from_slice(&read_bounded(&dir.join("manifest.json"), 4 * 1024 * 1024)?)?;
    if m.schema_version != 1 || m.kind != "passive_analysis" {
        return Err(Error::Invalid("unsupported analysis manifest".into()));
    }
    m.limits.validate()?;
    let mut analyzer = Analyzer::new(m.limits.clone());
    let mut integrity = Vec::new();
    let root = fs::canonicalize(dir)?;
    if m.complete && !m.artifacts.contains_key("events.jsonl") {
        integrity.push("manifest missing events integrity record".into());
    }
    let mut artifact_total = 0u64;
    for (name, a) in &m.artifacts {
        artifact_total = artifact_total
            .checked_add(a.size_bytes)
            .ok_or_else(|| Error::Limit("artifact size overflow".into()))?;
        if artifact_total > m.limits.output_bytes {
            return Err(Error::Limit("bundle artifact read budget".into()));
        }
        let path = Path::new(name);
        if path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(Error::Invalid("unsafe artifact path".into()));
        }
        let full = dir.join(path);
        if fs::canonicalize(&full).is_ok_and(|p| !p.starts_with(&root)) {
            return Err(Error::Invalid("artifact escapes bundle directory".into()));
        }
        if fs::symlink_metadata(&full).is_ok_and(|s| s.file_type().is_symlink()) {
            return Err(Error::Invalid("artifact symlinks are unsupported".into()));
        }
        match artifact(&full, a.size_bytes) {
            Ok(data) if data.size_bytes == a.size_bytes && data.sha256 == a.sha256 => {}
            _ => integrity.push(format!("missing or changed artifact: {name}")),
        }
    }
    let journal_path = dir.join("events.jsonl");
    if fs::canonicalize(&journal_path).is_ok_and(|p| !p.starts_with(&root))
        || fs::symlink_metadata(&journal_path).is_ok_and(|s| s.file_type().is_symlink())
    {
        return Err(Error::Invalid("journal symlinks are unsupported".into()));
    }
    let journal = match File::open(&journal_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut summary = analyzer.summary(&m.run_id, false);
            summary.gaps.push("missing events.jsonl".into());
            summary.gaps.extend(integrity);
            return Ok(summary);
        }
        Err(e) => return Err(e.into()),
    };
    let mut reader = BufReader::new(journal);
    let mut seq = 0;
    let mut elapsed = 0;
    let mut total = 0;
    loop {
        let mut line = Vec::new();
        let n = (&mut reader)
            .take(m.limits.record_bytes as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if n > m.limits.record_bytes || total > m.limits.journal_bytes {
            return Err(Error::Limit("journal read budget".into()));
        }
        if !line.ends_with(b"\n") {
            integrity.push("truncated final event".into());
            break;
        }
        let e: AnalysisEvent = serde_json::from_slice(&line)?;
        seq += 1;
        if e.schema_version != 1
            || e.run_id != m.run_id
            || e.sequence != seq
            || e.elapsed_ms < elapsed
            || OffsetDateTime::parse(&e.received_at, &Rfc3339).is_err()
        {
            return Err(Error::Invalid(format!(
                "invalid event envelope at sequence {seq}"
            )));
        }
        elapsed = e.elapsed_ms;
        if e.evidence_refs.iter().any(|r| !m.artifacts.contains_key(r)) {
            integrity.push(format!("unverified evidence at event {seq}"));
        }
        if let Err(e) = analyzer.apply(&e) {
            integrity.push(e.to_string());
            break;
        }
    }
    let mut s = analyzer.summary(&m.run_id, m.complete);
    if !integrity.is_empty() {
        s.coverage = "partial".into();
        s.gaps.extend(integrity);
        s.findings.clear();
    }
    Ok(s)
}
