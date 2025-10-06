use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::{net, time};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// Resolves current public IPv4 address
/// Resolution order:
/// 1) STUN (stun.l.google.com:19302, 6s timeout)
/// 2) HTTP (http://api.myip.la/en?json, 6s timeout)
pub async fn resolve_public_ipv4() -> Option<Ipv4Addr> {
    // STUN
    if let Some(ip) = get_ip_stun().await.ok().flatten() {
        return Some(ip);
    }

    // HTTP as string then parse
    match get_ip_http().await {
        Ok(Some(ip_str)) => ip_str.parse().ok(),
        _ => None,
    }
}

/// Same as resolve_public_ipv4 but returns String
pub async fn resolve_public_ipv4_string() -> Option<String> {
    resolve_public_ipv4().await.map(|ip| ip.to_string())
}

fn build_stun_binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    // type: Binding Request (0x0001)
    buf[0] = 0x00;
    buf[1] = 0x01;
    // length: 0
    buf[2] = 0x00;
    buf[3] = 0x00;
    // magic cookie 0x2112A442
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // transaction id
    buf[8..20].copy_from_slice(txid);
    buf
}

/// Public for testing/diagnostics
pub fn parse_xor_mapped_v4(resp: &[u8], _txid: &[u8; 12]) -> Option<Ipv4Addr> {
    if resp.len() < 20 {
        return None;
    }
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
    if resp.len() < 20 + msg_len {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= 20 + msg_len {
        let atype = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
        let alen = u16::from_be_bytes([resp[offset + 2], resp[offset + 3]]) as usize;
        offset += 4;
        if offset + alen > resp.len() {
            return None;
        }
        if atype == 0x0020 {
            // XOR-MAPPED-ADDRESS
            if alen < 8 {
                return None;
            }
            let family = resp[offset + 1];
            if family != 0x01 {
                return None;
            }
            let xport = u16::from_be_bytes([resp[offset + 2], resp[offset + 3]]);
            let _port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            let mut xaddr = [0u8; 4];
            xaddr.copy_from_slice(&resp[offset + 4..offset + 8]);
            let addr_be = u32::from_be_bytes(xaddr) ^ STUN_MAGIC_COOKIE;
            let octets = addr_be.to_be_bytes();
            return Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        }
        let pad = (4 - (alen % 4)) % 4;
        offset += alen + pad;
    }
    None
}

async fn get_ip_stun() -> Result<Option<Ipv4Addr>, std::io::Error> {
    use rand::RngCore;
    let mut txid = [0u8; 12];
    rand::rng().fill_bytes(&mut txid);
    let req = build_stun_binding_request(&txid);

    let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let socket = net::UdpSocket::bind(local).await?;

    // resolve stun.l.google.com:19302
    let addrs: Vec<SocketAddr> = net::lookup_host(("stun.l.google.com", 19302)).await?.collect();
    if let Some(target) = addrs.iter().find(|sa| sa.is_ipv4()).cloned().or_else(|| addrs.get(0).cloned()) {
        let _ = socket.send_to(&req, target).await?;
        let mut buf = [0u8; 1500];
        match time::timeout(Duration::from_millis(6000), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _addr))) => Ok(parse_xor_mapped_v4(&buf[..n], &txid)),
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

async fn get_ip_http() -> Result<Option<String>, std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = "api.myip.la";
    let port = 80;
    let req = b"GET /en?json HTTP/1.1\r\nHost: api.myip.la\r\nConnection: close\r\n\r\n";

    let stream = match time::timeout(Duration::from_millis(6000), net::TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };

    let mut stream = stream;
    if time::timeout(Duration::from_millis(6000), stream.write_all(req)).await.is_err() {
        return Ok(None);
    }

    let mut buf = Vec::with_capacity(4096);
    match time::timeout(Duration::from_millis(6000), async {
        let mut tmp = [0u8; 2048];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    {
        Ok(Ok(())) => {}
        _ => return Ok(None),
    }

    // Split headers and body
    let mut body = &buf[..];
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        body = &buf[pos + 4..];
    }

    // Try to handle simple chunked transfer encoding
    let is_chunked = {
        let headers = &buf[..buf.len().saturating_sub(body.len() + 4)];
        let headers_str = String::from_utf8_lossy(headers).to_ascii_lowercase();
        headers_str.contains("transfer-encoding: chunked")
    };

    let body_bytes = if is_chunked {
        match decode_chunked(body) {
            Some(b) => b,
            None => body.to_vec(),
        }
    } else {
        body.to_vec()
    };

    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        if let Some(ip) = v.get("ip").and_then(|x| x.as_str()) {
            return Ok(Some(ip.to_string()));
        }
    }
    Ok(None)
}

fn decode_chunked(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        // read size line
        let pos = body.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&body[..pos]).ok()?.trim();
        let size = usize::from_str_radix(size_str.trim_end_matches(|c: char| c.is_ascii_whitespace()), 16).ok()?;
        body = &body[pos + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..]; // skip CRLF
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_v4_parsing() {
        // Construct a fake response with XOR-MAPPED-ADDRESS
        let txid = [1u8; 12];
        let mut resp = Vec::new();
        // header
        resp.extend_from_slice(&[0x01, 0x01, 0x00, 0x0c]); // success response, 12 bytes attrs
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txid);
        // attribute header: type 0x0020, len 8
        resp.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
        // value: 0, family=1, xport, xaddr
        let port: u16 = 54321;
        let xport = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&xport.to_be_bytes());
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let xaddr = u32::from_be_bytes(ip.octets()) ^ STUN_MAGIC_COOKIE;
        resp.extend_from_slice(&xaddr.to_be_bytes());

        let parsed = parse_xor_mapped_v4(&resp, &txid).unwrap();
        assert_eq!(parsed, ip);
    }
}
