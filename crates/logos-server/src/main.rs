//! Logos relay binary. Binds `LOGOS_ADDR` (default 127.0.0.1:8787).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let addr: std::net::SocketAddr = std::env::var("LOGOS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()
        .expect("valid LOGOS_ADDR");
    let key_path = std::env::var("LOGOS_KEY").unwrap_or_else(|_| "logos-server-key".to_string());
    let data_dir = std::env::var("LOGOS_DATA").unwrap_or_else(|_| "logos-server-data".to_string());
    tracing::info!("Logos relay listening on {addr} (EXPERIMENTAL — UNAUDITED)");
    logos_server::run(addr, &key_path, &data_dir).await
}
