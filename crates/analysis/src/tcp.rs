//! Bounded directional TCP reassembly. Conflicting or unverifiable overlaps poison the stream.
use crate::{Error, Result};
use std::collections::VecDeque;
pub struct TcpStream {
    next: Option<u32>,
    pending: VecDeque<Option<u8>>,
    history: VecDeque<u8>,
    limit: usize,
    failed: bool,
}
impl TcpStream {
    pub fn new(first_sequence: Option<u32>, limit: usize) -> Self {
        Self {
            next: first_sequence,
            pending: VecDeque::new(),
            history: VecDeque::new(),
            limit,
            failed: false,
        }
    }
    pub fn push(&mut self, sequence: u32, payload: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Invalid(
                "TCP stream is unusable after a gap/conflict".into(),
            ));
        }
        let result = self.insert(sequence, payload);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn insert(&mut self, sequence: u32, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.is_empty() {
            return Ok(vec![]);
        }
        let next = *self.next.get_or_insert(sequence);
        if payload.len() > self.limit || self.limit > i32::MAX as usize {
            return Err(Error::Limit("TCP stream window".into()));
        }
        for (i, byte) in payload.iter().enumerate() {
            let delta = sequence.wrapping_add(i as u32).wrapping_sub(next) as i32;
            if delta < 0 {
                let behind = delta.unsigned_abs() as usize;
                if behind > self.history.len() {
                    return Err(Error::Invalid(
                        "TCP overlap precedes retained history or explicit start boundary".into(),
                    ));
                }
                if self.history[self.history.len() - behind] != *byte {
                    return Err(Error::Invalid("conflicting TCP retransmission".into()));
                }
            } else {
                let at = delta as usize;
                if at >= self.limit {
                    return Err(Error::Limit("TCP out-of-order window".into()));
                }
                if at >= self.pending.len() {
                    self.pending.resize(at + 1, None);
                }
                if self.pending[at].is_some_and(|old| old != *byte) {
                    return Err(Error::Invalid("conflicting TCP overlap".into()));
                }
                self.pending[at] = Some(*byte);
            }
        }
        let mut out = Vec::new();
        while let Some(Some(_)) = self.pending.front() {
            let b = self.pending.pop_front().flatten().expect("present byte");
            out.push(b);
            self.history.push_back(b);
            if self.history.len() > self.limit {
                self.history.pop_front();
            }
        }
        self.next = Some(next.wrapping_add(out.len() as u32));
        Ok(out)
    }
    pub fn finish(&self) -> Result<()> {
        if self.failed || !self.pending.is_empty() {
            Err(Error::Invalid(
                "TCP stream ended with a gap or conflict".into(),
            ))
        } else {
            Ok(())
        }
    }
}
