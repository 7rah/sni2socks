use fast_socks5::client::Config;
use fast_socks5::client::Socks5Stream;
use log::error;
use log::info;
use log::LevelFilter;
use smol::future;
use smol::io;
use smol::net::{TcpListener, TcpStream};
use std::io::{Error, Result};
use std::str::from_utf8;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};

fn new_error<T: ToString>(message: T) -> Error {
    io::Error::new(io::ErrorKind::Other, message.to_string())
}

fn parse_tls_connection(buf: &[u8]) -> Result<String> {
    let (_, res) = parse_tls_plaintext(&buf).map_err(|_| new_error("unexpected protocol"))?;
    match &res.msg[0] {
        Handshake(ClientHello(contents)) => {
            let ext = contents
                .ext
                .ok_or(())
                .map_err(|_| new_error("unable to find tls extensions"))?;

            let (_, exts) = parse_tls_extensions(ext)
                .map_err(|_| new_error("unable to parse tls extensions"))?;

            let v = exts
                .iter()
                .find_map(|i| match i {
                    TlsExtension::SNI(v) => Some(v),
                    _ => None,
                })
                .ok_or(())
                .map_err(|_| new_error("unable to find tls extension SNI"))?;

            let name = from_utf8(v[0].1).unwrap().to_string();
            Ok(name)
        }
        _ => Err(new_error("unexpected handshake type")),
    }
}

async fn serve(stream: TcpStream) -> std::io::Result<()> {
    let mut buf: [u8; 2048] = [0; 2048];
    stream.peek(&mut buf).await?;

    let domain = parse_tls_connection(&buf)?;
    info!("accepted {}", domain);


    let config = Config::default();
    let socks = Socks5Stream::connect("192.168.1.1:1080", domain, 443, config)
        .await
        .map_err(new_error)?;

    let (stream_reader, stream_writer) = io::split(stream);
    let (socks_reader, socks_writer) = io::split(socks);

    future::race(
        async {
            io::copy(stream_reader, socks_writer).await.map_err(|e| new_error(e.to_string()))
        },
        async {
            io::copy(socks_reader, stream_writer).await.map_err(|e| new_error(e.to_string()))
        },
    )
    .await?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    smol::block_on(async {
        let listener = TcpListener::bind("0.0.0.0:443").await?;
        let _ = env_logger::builder()
            .filter_module("sni2socks", LevelFilter::Info)
            .try_init();

        loop {
            match listener.accept().await {
                Ok((stream, _)) => smol::spawn(async {
                    match serve(stream).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("{}", e.to_string())
                        }
                    }
                })
                .detach(),
                Err(e) => {
                    error!("{}", e.to_string())
                }
            }
        }
    })
}
