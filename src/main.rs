use anyhow::anyhow;
use anyhow::Result;
use std::env;
use std::str;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};
use tokio::io::split;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio_socks::tcp::Socks5Stream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let listen = env::args().nth(1).unwrap_or_else(|| {
        println!("Expect listen addr,use default(0.0.0.0:443)");
        "0.0.0.0:443".to_string()
    });
    let proxy = env::args().nth(2).unwrap_or_else(|| {
        println!("Expect socks5 proxy addr,use default(192.168.1.1:1080)");
        "192.168.1.1:1080".to_string()
    });
    let listener = TcpListener::bind(listen).await.unwrap();

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

#[inline]
async fn serve(proxy: &str, inbound: TcpStream) -> Result<()> {
    let buf = &mut [0u8; 2048];
    inbound.peek(buf).await?;
    let domain = parse_sni(buf)?;
    let outbound = Socks5Stream::connect(proxy, domain + ":443").await?;

    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = split(outbound);
    let c1 = copy_tcp(&mut ri, &mut wo);
    let c2 = copy_tcp(&mut ro, &mut wi);

    let e = tokio::select! {
        e = c1 => {e}
        e = c2 => {e}
    };
    e?;

    let mut inbound = ri.unsplit(wi);
    let mut outbound = ro.unsplit(wo);
    let _ = inbound.shutdown().await;
    let _ = outbound.shutdown().await;

    Ok(())
}

#[inline]
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

#[inline]
async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
) -> Result<()> {
    let mut buf = [0u8; 16384 * 3];
    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        w.write(&buf[..len]).await?;
        w.flush().await?;
    }
    Ok(())
}
