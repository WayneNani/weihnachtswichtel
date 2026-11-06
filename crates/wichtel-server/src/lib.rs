//! Weihnachtswichtel server: a "dumb mailbox" for ciphertexts and masked vectors.
//!
//! The server never learns the assignment: it stores public keys, encrypted names, the running
//! XOR of the DC-net vectors and the reveals of the chosen attempt only (Konzept §6–§7,
//! Spec §10, §14). Modules:
//! - [`app`] – state machine, aggregation, jobs (HTTP-independent)
//! - [`routes`] – axum routes (docs/api.md)
//! - [`store`] – persistence (`Store` trait, Turso implementation, SQL migrations)
//! - [`protocol`] – the `wichtel-core` operations the server uses, behind a trait
//! - [`push`] – payload-less Web-Push with VAPID
//! - [`events`] – per-group broadcast for SSE
//! - [`web`] – security headers, privacy-preserving logging, static assets

#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod error;
pub mod events;
pub mod protocol;
pub mod push;
pub mod ratelimit;
pub mod routes;
pub mod store;
pub mod web;

use std::sync::Arc;
use std::time::Duration;

pub use app::App;
pub use config::Config;

/// Spawn the minutely background job (schedules, reminders, expiry, `VACUUM`).
pub fn spawn_jobs(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            app.run_jobs().await;
        }
    })
}
