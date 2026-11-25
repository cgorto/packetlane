//! The functional core. Nothing in here performs I/O; `tests/purity.rs`
//! enforces that.

pub mod api;
pub mod args;
pub mod ccsds;
pub mod checksum;
pub mod config;
pub mod continuity;
pub mod cosmos_defs;
pub mod cross;
pub mod decode;
pub mod format;
pub mod frame;
pub mod http;
pub mod ingest;
pub mod paths;
pub mod sql;
pub mod synth;
pub mod textlog;
pub mod time;
