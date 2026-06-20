//! Logos relay binary. Binds `LOGOS_ADDR` (default 127.0.0.1:8787).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let addr: std::net::SocketAddr = std::env::var("LOGOS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()
        .expect("valid LOGOS_ADDR");
    tracing::info!("Logos relay listening on {addr} (EXPERIMENTAL — UNAUDITED)");
    logos_server::run(addr).await
}
