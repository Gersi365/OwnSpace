use std::{env, fs, net::SocketAddr, process::ExitCode, time::Duration};

use prw_control_transport::ControlTlsClientConfig;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("phase129_tls_probe=failed kind={error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let addr: SocketAddr = args
        .next()
        .ok_or("missing_addr")?
        .parse()
        .map_err(|_| "invalid_addr")?;
    let server_name = args.next().ok_or("missing_server_name")?;
    let root_path = args.next().ok_or("missing_root_path")?;
    if args.next().is_some() {
        return Err("unexpected_argument");
    }
    let root = fs::read(root_path).map_err(|_| "root_read")?;
    let config = ControlTlsClientConfig::new(
        addr,
        server_name,
        &[root],
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(3),
    )
    .map_err(|_| "config")?;
    let _stream = config.connect().map_err(|_| "connect")?;
    println!("phase129_tls=pass protocol=tls1.3 alpn=prw-control/1");
    Ok(())
}
