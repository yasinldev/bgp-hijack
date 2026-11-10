//! Single-owner durable JSONL recording and bounded prefix recovery.
//! A clean journal EOF never proves that an experiment or cleanup completed.

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

use crate::{
    SCHEMA_VERSION,
    evidence::{ArtifactMetadata, EventEnvelope, EventKind, Manifest},
    model::{AddressFamily, CanonicalPrefix, PeerId},
};

#[derive(Debug, Clone, Copy)]
pub struct JournalLimits {
    /// Includes the terminating newline.
    pub max_record_bytes: usize,
    pub max_journal_bytes: u64,
    pub max_manifest_bytes: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_record_bytes: 1024 * 1024,
            max_journal_bytes: 64 * 1024 * 1024,
            max_manifest_bytes: 4 * 1024 * 1024,
        }
    }
}

impl JournalLimits {
    fn validate(self) -> Result<(), JournalError> {
        if self.max_record_bytes < 2
            || self.max_manifest_bytes == 0
            || self.max_record_bytes as u128 > u128::from(self.max_journal_bytes)
        {
            return Err(JournalError::Invalid("invalid journal limits"));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal I/O: {0}")]
    Io(#[from] io::Error),
    #[error("journal JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("journal limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid journal: {0}")]
    Invalid(&'static str),
    #[error("journal writer is unusable after an I/O error")]
    WriterFailed,
}

/// Producers supply observations only; identity, ordering and time belong to the writer.
#[derive(Debug, Clone)]
pub struct EventDraft {
    pub kind: EventKind,
    pub source_node: Option<String>,
    pub peer_id: Option<PeerId>,
    pub address_family: Option<AddressFamily>,
    pub prefix: Option<CanonicalPrefix>,
    pub evidence_refs: Vec<String>,
    pub details: Map<String, Value>,
}

pub trait JournalClock {
    fn sample(&self) -> (OffsetDateTime, Duration);
}

pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl JournalClock for SystemClock {
    fn sample(&self) -> (OffsetDateTime, Duration) {
        (OffsetDateTime::now_utc(), self.start.elapsed())
    }
}

/// Storage boundary allows deterministic short-write, flush and sync fault tests.
pub trait DurableWrite: Write {
    fn sync_all(&mut self) -> io::Result<()>;
}

impl DurableWrite for File {
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

pub struct JournalWriter<C = SystemClock, S = File> {
    sink: S,
    clock: C,
    run_id: String,
    limits: JournalLimits,
    next_sequence: u64,
    last_elapsed_ms: u64,
    bytes: u64,
    failed: bool,
}

impl JournalWriter {
    pub fn create(
        path: &Path,
        manifest: Manifest,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        Self::create_with_clock(path, manifest, limits, SystemClock::default())
    }
}

impl<C: JournalClock> JournalWriter<C> {
    /// Creates a new directory only. Partial initialization is retained on error.
    pub fn create_with_clock(
        path: &Path,
        mut manifest: Manifest,
        limits: JournalLimits,
        clock: C,
    ) -> Result<Self, JournalError> {
        limits.validate()?;
        if manifest.schema_version != SCHEMA_VERSION || manifest.run_id.trim().is_empty() {
            return Err(JournalError::Invalid(
                "manifest requires schema version 1 and a nonempty run ID",
            ));
        }
        manifest.started_at = clock.sample().0.to_offset(UtcOffset::UTC);
        manifest.complete = false;
        manifest.artifacts = vec![ArtifactMetadata {
            path: "events.jsonl".into(),
            size_bytes: None,
            sha256: None,
            complete: false,
        }];
        let encoded = bounded_json(&manifest, limits.max_manifest_bytes, "manifest")?;
        fs::create_dir(path)?;
        let mut file = File::create_new(path.join("manifest.json"))?;
        crate::storage::persist(&mut file, &encoded)?;
        let sink = File::create_new(path.join("events.jsonl"))?;
        sink.sync_all()?;
        File::open(path)?.sync_all()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(Self {
            sink,
            clock,
            run_id: manifest.run_id,
            limits,
            next_sequence: 1,
            last_elapsed_ms: 0,
            bytes: 0,
            failed: false,
        })
    }
}

impl<C: JournalClock, S: DurableWrite> JournalWriter<C, S> {
    pub fn append(&mut self, draft: EventDraft) -> Result<EventEnvelope, JournalError> {
        if self.failed {
            return Err(JournalError::WriterFailed);
        }
        let (timestamp, elapsed) = self.clock.sample();
        let elapsed_ms =
            u64::try_from(elapsed.as_millis()).map_err(|_| JournalError::Limit("elapsed time"))?;
        if elapsed_ms < self.last_elapsed_ms {
            return Err(JournalError::Invalid("monotonic elapsed time regressed"));
        }
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::Limit("sequence number"))?;
        let event = EventEnvelope {
            schema_version: SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            sequence: self.next_sequence,
            timestamp: timestamp.to_offset(UtcOffset::UTC),
            elapsed_ms,
            kind: draft.kind,
            source_node: draft.source_node,
            peer_id: draft.peer_id,
            address_family: draft.address_family,
            prefix: draft.prefix,
            evidence_refs: draft.evidence_refs,
            details: draft.details,
        };
        let mut bytes = bounded_json(&event, self.limits.max_record_bytes - 1, "record")?;
        bytes.push(b'\n');
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(JournalError::Limit("journal"))?;
        if total > self.limits.max_journal_bytes {
            return Err(JournalError::Limit("journal"));
        }
        let result = crate::storage::persist(&mut self.sink, &bytes);
        if let Err(error) = result {
            self.failed = true;
            return Err(error.into());
        }
        self.bytes = total;
        self.next_sequence = next;
        self.last_elapsed_ms = elapsed_ms;
        Ok(event)
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::other("serialization limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json(
    value: &impl Serialize,
    limit: usize,
    name: &'static str,
) -> Result<Vec<u8>, JournalError> {
    let mut output = BoundedBuffer {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut output, value) {
        return Err(if output.exceeded {
            JournalError::Limit(name)
        } else {
            error.into()
        });
    }
    Ok(output.bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalReadStatus {
    Reading,
    CleanEof,
    TruncatedTail,
    Failed,
}

pub struct JournalReader<R> {
    source: R,
    run_id: String,
    limits: JournalLimits,
    next_sequence: u64,
    last_elapsed_ms: u64,
    bytes: u64,
    status: JournalReadStatus,
}

impl JournalReader<BufReader<File>> {
    /// Loads only fixed manifest/events filenames. Does not verify artifact hashes.
    pub fn open(path: &Path, limits: JournalLimits) -> Result<(Manifest, Self), JournalError> {
        limits.validate()?;
        let maximum = u64::try_from(limits.max_manifest_bytes)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(JournalError::Limit("manifest limit"))?;
        let mut bytes = Vec::new();
        File::open(path.join("manifest.json"))?
            .take(maximum)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limits.max_manifest_bytes {
            return Err(JournalError::Limit("manifest"));
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(JournalError::Invalid("unsupported manifest schema"));
        }
        let reader = Self::new(
            BufReader::new(File::open(path.join("events.jsonl"))?),
            manifest.run_id.clone(),
            limits,
        )?;
        Ok((manifest, reader))
    }
}

impl<R: BufRead> JournalReader<R> {
    pub fn new(source: R, run_id: String, limits: JournalLimits) -> Result<Self, JournalError> {
        limits.validate()?;
        if run_id.trim().is_empty() {
            return Err(JournalError::Invalid("empty expected run ID"));
        }
        Ok(Self {
            source,
            run_id,
            limits,
            next_sequence: 1,
            last_elapsed_ms: 0,
            bytes: 0,
            status: JournalReadStatus::Reading,
        })
    }

    pub fn status(&self) -> JournalReadStatus {
        self.status
    }

    fn read_record(&mut self) -> Result<Option<EventEnvelope>, JournalError> {
        let mut line = Vec::new();
        loop {
            let buffer = self.source.fill_buf()?;
            if buffer.is_empty() {
                self.status = if line.is_empty() {
                    JournalReadStatus::CleanEof
                } else {
                    JournalReadStatus::TruncatedTail
                };
                return Ok(None);
            }
            let newline = buffer.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(buffer.len(), |index| index + 1);
            if count > self.limits.max_record_bytes - line.len() {
                return Err(JournalError::Limit("record"));
            }
            let total = self
                .bytes
                .checked_add(count as u64)
                .ok_or(JournalError::Limit("journal"))?;
            if total > self.limits.max_journal_bytes {
                return Err(JournalError::Limit("journal"));
            }
            line.extend_from_slice(&buffer[..count]);
            self.source.consume(count);
            self.bytes = total;
            if newline.is_some() {
                break;
            }
        }
        let event: EventEnvelope = serde_json::from_slice(&line)?;
        if event.schema_version != SCHEMA_VERSION {
            return Err(JournalError::Invalid("unsupported event schema"));
        }
        if event.run_id != self.run_id {
            return Err(JournalError::Invalid("event belongs to another run"));
        }
        if event.sequence != self.next_sequence {
            return Err(JournalError::Invalid(
                "event sequence is not contiguous from one",
            ));
        }
        if event.elapsed_ms < self.last_elapsed_ms {
            return Err(JournalError::Invalid("event elapsed time regressed"));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::Limit("sequence number"))?;
        self.last_elapsed_ms = event.elapsed_ms;
        Ok(Some(event))
    }
}

impl<R: BufRead> Iterator for JournalReader<R> {
    type Item = Result<EventEnvelope, JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.status != JournalReadStatus::Reading {
            return None;
        }
        match self.read_record() {
            Ok(event) => event.map(Ok),
            Err(error) => {
                self.status = JournalReadStatus::Failed;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FaultSink {
        bytes: Vec<u8>,
        fail: &'static str,
        syncs: usize,
    }
    impl Write for FaultSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail == "write" && !self.bytes.is_empty() {
                return Err(io::Error::other("injected write failure"));
            }
            let count = bytes.len().min(7);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail == "flush" {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }
    impl DurableWrite for FaultSink {
        fn sync_all(&mut self) -> io::Result<()> {
            self.syncs += 1;
            if self.fail == "sync" {
                Err(io::Error::other("injected sync failure"))
            } else {
                Ok(())
            }
        }
    }

    fn draft() -> EventDraft {
        EventDraft {
            kind: EventKind::EvidenceGap,
            source_node: None,
            peer_id: None,
            address_family: None,
            prefix: None,
            evidence_refs: vec![],
            details: Map::from_iter([("reason".into(), Value::from("test observation"))]),
        }
    }

    #[test]
    fn short_writes_complete_and_each_append_syncs() {
        let mut writer = JournalWriter {
            sink: FaultSink {
                bytes: vec![],
                fail: "",
                syncs: 0,
            },
            clock: SystemClock::default(),
            run_id: "test".into(),
            limits: JournalLimits::default(),
            next_sequence: 1,
            last_elapsed_ms: 0,
            bytes: 0,
            failed: false,
        };
        writer.append(draft()).unwrap();
        writer.append(draft()).unwrap();
        assert_eq!(writer.sink.syncs, 2);
        let reader = JournalReader::new(
            io::Cursor::new(writer.sink.bytes),
            "test".into(),
            JournalLimits::default(),
        )
        .unwrap();
        assert_eq!(reader.collect::<Result<Vec<_>, _>>().unwrap().len(), 2);
    }

    #[test]
    fn write_flush_and_sync_errors_poison_the_writer() {
        for fail in ["write", "flush", "sync"] {
            let mut writer = JournalWriter {
                sink: FaultSink {
                    bytes: vec![],
                    fail,
                    syncs: 0,
                },
                clock: SystemClock::default(),
                run_id: "test".into(),
                limits: JournalLimits::default(),
                next_sequence: 1,
                last_elapsed_ms: 0,
                bytes: 0,
                failed: false,
            };
            assert!(matches!(writer.append(draft()), Err(JournalError::Io(_))));
            let before = writer.sink.bytes.clone();
            assert!(matches!(
                writer.append(draft()),
                Err(JournalError::WriterFailed)
            ));
            assert_eq!(writer.sink.bytes, before);
            assert_eq!(writer.next_sequence, 1);
        }
    }
}
