//! Weihnachtswichtel server (Phase-0 skeleton: health route only).

use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = Router::new().route("/api/health", get(|| async { "ok" }));
    let addr = std::env::var("WICHTEL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind listen address");
    tracing::info!(%addr, "listening");
    axum::serve(listener, app).await.expect("server error");
}
