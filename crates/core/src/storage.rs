//! Shared storage primitives. Success means the bytes reached the durable-write boundary.
use crate::journal::DurableWrite;
use std::io;

pub fn persist<S: DurableWrite>(sink: &mut S, bytes: &[u8]) -> io::Result<()> {
    sink.write_all(bytes)?;
    sink.flush()?;
    sink.sync_all()
}
