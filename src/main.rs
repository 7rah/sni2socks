use anyhow::anyhow;
use anyhow::Result;
use std::env;
use std::str;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};
use tokio::io::copy;
use tokio::io::split;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio_socks::tcp::Socks5Stream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let proxy = env::args().nth(1).unwrap_or_else(|| {
        println!("Expect socks5 proxy addr,use default(127.0.0.1:1080)");
        "127.0.0.1:1080".to_string()
    });
    let listener = TcpListener::bind("127.0.0.1:443").await.unwrap();

    loop {
        let proxy = proxy.clone();
        let (inbound, _) = listener.accept().await?;

        spawn(async move {
            match serve(&proxy, inbound).await {
                Ok(_) => {}
                Err(e) => println!("Error: {}", e),
            }
        });
    }
}

async fn serve(proxy: &str, inbound: TcpStream) -> Result<()> {
    let buf = &mut [0u8; 2048];
    inbound.peek(buf).await?;
    let domain = parse_sni(buf)?;
    let outbound = Socks5Stream::connect(proxy, domain + ":443").await?;

    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = split(outbound);
    let client_to_server = async {
        copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

fn parse_sni(buf: &[u8]) -> Result<String> {
    let (_, res) = parse_tls_plaintext(&buf).map_err(|_| anyhow!("unexpected protocol"))?;
    match &res.msg[0] {
        Handshake(ClientHello(contents)) => {
            let ext = contents
                .ext
                .ok_or(anyhow!("unable to find tls extensions"))?;

            let (_, exts) =
                parse_tls_extensions(ext).map_err(|_| anyhow!("unable to parse tls extensions"))?;

            let v = exts
                .iter()
                .find_map(|i| match i {
                    TlsExtension::SNI(v) => Some(v),
                    _ => None,
                })
                .ok_or(anyhow!("unable to find tls extension SNI"))?;

            let domain = str::from_utf8(v[0].1).unwrap().to_string();
            Ok(domain)
        }
        _ => Err(anyhow!("unexpected handshake type")),
    }
}
