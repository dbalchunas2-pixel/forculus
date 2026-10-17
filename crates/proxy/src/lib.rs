//! Forculus proxy — HTTP/HTTPS forward proxy core.
//!
//! This crate implements a forward proxy that intercepts both plain HTTP and
//! HTTPS (via CONNECT tunnelling with TLS MITM) traffic, logging every request
//! as structured JSON.
#![forbid(unsafe_code)]

pub mod context;
pub mod error_response;
pub mod forward;
pub mod handler;
pub mod logging;
pub mod pincheck;
pub mod pins;
pub mod server;
pub mod tls;
pub mod toolmap;
pub mod tunnel;
