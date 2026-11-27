//! The imperative shell: everything that touches the outside world.
//! It holds no rules of its own; it gathers inputs, asks `pure` what they
//! mean, and carries out the answer.

pub mod browse;
pub mod cli;
pub mod files;
pub mod ingest;
pub mod segment;
pub mod server;
pub mod store;
