//! Weihnachtswichtel server binary. Configuration: see [`wichtel_server::config`].

use std::net::SocketAddr;
use std::sync::Arc;

use wichtel_server::app::SystemClock;
use wichtel_server::protocol::CoreOps;
use wichtel_server::push::ReqwestPushClient;
use wichtel_server::store::TursoStore;
use wichtel_server::{App, Config, routes, spawn_jobs};

#[tokio::main]
async fn main() {
    // No ANSI colours, no targets: logs carry neither IPs nor user agents (Konzept §7.5).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    let store = TursoStore::open(&cfg.db_path).await.expect("open database");
    let push = ReqwestPushClient::new().expect("build push client");
    let addr = cfg.addr;
    let app = App::new(
        cfg,
        Arc::new(store),
        Arc::new(CoreOps),
        Arc::new(SystemClock),
        Arc::new(push),
    )
    .await
    .expect("initialize application");
    spawn_jobs(app.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listen address");
    tracing::info!(%addr, "listening");
    axum::serve(
        listener,
        routes::router(app).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .expect("server error");
}
