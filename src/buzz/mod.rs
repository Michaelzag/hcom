//! Blocking Buzz/Nostr protocol primitives and transports.

// Connector callers land in the next PR; keep the allowance at module scope.
#![allow(dead_code)]

pub mod nostr;
pub mod relay;

#[cfg(test)]
pub(crate) mod testing;
