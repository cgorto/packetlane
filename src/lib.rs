//! packetlane: read-only tooling for CCSDS space packet logs.
//!
//! The crate is split in two (see `docs/architecture.md`):
//!
//! - [`pure`]: the functional core. Values in, values out. No files, sockets,
//!   clocks, randomness, environment, processes or database handles.
//! - [`shell`]: the imperative shell. It does the I/O and calls into `pure`
//!   for every decision.

pub mod pure;
pub mod shell;
