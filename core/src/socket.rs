use crate::metrics::Metrics;
use std::io::Result;
use std::net::SocketAddr;

/// Trait for UDP socket operations with optional dump/replay functionality
#[async_trait::async_trait]
pub trait UdpSocketExt: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;

    /// Wrapper function that calls recv_from and increments metrics
    async fn recv_from_with_metrics(&self, buf: &mut [u8], metrics: &Metrics) -> Result<(usize, SocketAddr)> {
        let result = self.recv_from(buf).await?;
        metrics.add_incoming_udp_packet(result.0);
        Ok(result)
    }

    /// Wrapper function that calls send_to and increments metrics
    async fn send_to_with_metrics(&self, buf: &[u8], target: SocketAddr, metrics: &Metrics) -> Result<usize> {
        let result = self.send_to(buf, target).await?;
        metrics.add_outgoing_udp_packet(result);
        Ok(result)
    }
}

#[cfg(test)]
pub struct MockSocket {
    recv_data: Vec<u8>,
    recv_addr: SocketAddr,
}

#[cfg(test)]
impl MockSocket {
    pub fn new() -> Self {
        Self::with_data_and_src(vec![], "127.0.0.1:1234".parse().unwrap())
    }

    fn with_data_and_src(recv_data: Vec<u8>, recv_addr: SocketAddr) -> Self {
        Self { recv_data, recv_addr }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl UdpSocketExt for MockSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let len = self.recv_data.len().min(buf.len());
        buf[..len].copy_from_slice(&self.recv_data[..len]);
        Ok((len, self.recv_addr))
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> Result<usize> {
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn test_recv_from_with_metrics() {
        let socket = MockSocket::with_data_and_src(vec![1, 2, 3, 4], "127.0.0.1:1234".parse().unwrap());
        let metrics = Metrics::new();
        let mut buf = vec![0u8; 10];

        let (len, addr) = socket.recv_from_with_metrics(&mut buf, &metrics).await.unwrap();

        assert_eq!(len, 4);
        assert_eq!(addr.to_string(), "127.0.0.1:1234");

        // Check that metrics were incremented
        let snapshot = metrics.get_snapshot();
        assert_eq!(snapshot.udp.incoming_packets, 1);
        assert_eq!(snapshot.udp.incoming_bytes, 4);
    }

    #[tokio::test]
    async fn test_send_to_with_metrics() {
        let socket = MockSocket::with_data_and_src(vec![1, 2, 3, 4], "127.0.0.1:1234".parse().unwrap());
        let metrics = Metrics::new();
        let data = vec![1, 2, 3, 4, 5];
        let target = "127.0.0.1:5678".parse().unwrap();

        let sent = socket.send_to_with_metrics(&data, target, &metrics).await.unwrap();

        assert_eq!(sent, 5);

        // Check that metrics were incremented
        let snapshot = metrics.get_snapshot();
        assert_eq!(snapshot.udp.outgoing_packets, 1);
        assert_eq!(snapshot.udp.outgoing_bytes, 5);
    }
}
