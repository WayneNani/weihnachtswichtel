//! Weihnachtswichtel server binary. Configuration: see [`wichtel_server::config`].

use std::net::SocketAddr;
use std::sync::Arc;

use wichtel_server::app::SystemClock;
use wichtel_server::protocol::CoreOps;
use wichtel_server::push::ReqwestPushClient;
use wichtel_server::store::TursoStore;
use wichtel_server::{App, Config, routes, spawn_jobs};

/// Resolves on Ctrl-C (SIGINT) or SIGTERM (`docker stop`, systemd).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

#[tokio::main]
async fn main() {
    // Logs carry neither IPs nor user agents nor path parameters (Konzept §7.5).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,turso=warn,turso_core=warn".into()),
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
    let jobs = spawn_jobs(app.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listen address");
    tracing::info!(%addr, "listening");
    let app2 = app.clone();
    axum::serve(
        listener,
        routes::router(app.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        // SSE streams never end on their own; close them so the graceful shutdown completes.
        app2.shutdown();
    })
    .await
    .expect("server error");
    jobs.abort();
    // Do not leave deleted data in free pages until the next start.
    app.maybe_vacuum(true).await;
}
