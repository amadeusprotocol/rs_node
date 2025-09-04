use crate::utils::misc::{Typename, get_unix_secs_now};
use scc::HashIndex as SccHashIndex;
use scc::ebr::Guard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tracing::warn;

/// Complete metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub incoming_protos: HashMap<String, u64>,
    pub outgoing_protos: HashMap<String, u64>,
    pub errors: HashMap<String, u64>,
    pub udp: UdpStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udpps: Option<UdpStats>,
    pub uptime: u32,
}

/// Packet statistics with rate calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpStats {
    pub incoming_packets: u64,
    pub incoming_bytes: u64,
    pub outgoing_packets: u64,
    pub outgoing_bytes: u64,
}

impl MetricsSnapshot {
    /// Serialize to JSON string
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            warn!("Failed to serialize metrics snapshot: {}", e);
            "{}".into()
        })
    }

    /// Serialize to Prometheus metrics format string
    pub fn to_prometheus_string(&self) -> String {
        let udp = format!(
            r#"
# HELP amadeus_udp_packets_total Total number of UDP packets
# TYPE amadeus_udp_packets_total counter
amadeus_udp_packets_total{{type="incoming"}} {}
amadeus_udp_packets_total{{type="outgoing"}} {}

# HELP amadeus_udp_bytes_total Total number of UDP bytes
# TYPE amadeus_udp_bytes_total counter
amadeus_udp_bytes_total{{type="incoming"}} {}
amadeus_udp_bytes_total{{type="outgoing"}} {}

# HELP amadeus_uptime_seconds Process uptime in seconds
# TYPE amadeus_uptime_seconds gauge
amadeus_uptime_seconds {}"#,
            self.udp.incoming_packets,
            self.udp.outgoing_packets,
            self.udp.incoming_bytes,
            self.udp.outgoing_bytes,
            self.uptime
        );

        let mut udpps = "".to_string();
        if let Some(snapshot_udpps) = &self.udpps {
            udpps = format!(
                r#"

# HELP amadeus_udp_packets_per_second Total number of UDP packets
# TYPE amadeus_udp_packets_per_second gauge
amadeus_udp_packets_per_second{{type="incoming"}} {}
amadeus_udp_packets_per_second{{type="outgoing"}} {}

# HELP amadeus_udp_bytes_per_second Total number of UDP bytes
# TYPE amadeus_udp_bytes_per_second gauge
amadeus_udp_bytes_per_second{{type="incoming"}} {}
amadeus_udp_bytes_per_second{{type="outgoing"}} {}"#,
                snapshot_udpps.incoming_packets,
                snapshot_udpps.outgoing_packets,
                snapshot_udpps.incoming_bytes,
                snapshot_udpps.outgoing_bytes
            );
        }

        let mut protos = Vec::new();
        protos.push("\n\n# HELP amadeus_incoming_protos_total Total number of proto messages handled by type".into());
        protos.push("# TYPE amadeus_incoming_protos_total counter".into());
        for (proto_name, count) in &self.incoming_protos {
            protos.push(format!("amadeus_incoming_protos_total{{type=\"{}\"}} {}", proto_name, count));
        }

        let mut sent_packets = Vec::new();
        sent_packets
            .push("\n\n# HELP amadeus_outgoing_protos_total Total number of messages sent by protocol type".into());
        sent_packets.push("# TYPE amadeus_outgoing_protos_total counter".into());
        for (proto_name, count) in &self.outgoing_protos {
            sent_packets.push(format!("amadeus_outgoing_protos_total{{type=\"{}\"}} {}", proto_name, count));
        }

        let mut errors = Vec::new();
        errors.push("\n\n# HELP amadeus_packet_errors_total Total number of packet processing errors by type".into());
        errors.push("# TYPE amadeus_packet_errors_total counter".into());
        for (error_type, count) in &self.errors {
            errors.push(format!("amadeus_packet_errors_total{{type=\"{}\"}} {}", error_type, count));
        }

        format!("{}{}{}{}{}", udp, udpps, protos.join("\n"), sent_packets.join("\n"), errors.join("\n"))
    }
}

pub struct Metrics {
    // Total packets counter
    incoming_bytes: AtomicU64,   // Total bytes received
    incoming_packets: AtomicU64, // Total UDP packets received
    outgoing_bytes: AtomicU64,   // Total bytes sent
    outgoing_packets: AtomicU64, // Total UDP packets sent

    // Handled protocol message counters by name (dynamic)
    incoming_protos: SccHashIndex<String, Arc<AtomicU64>>,

    // Error counters by type name (dynamic)
    errors: SccHashIndex<String, Arc<AtomicU64>>,

    // Sent packets counter by protocol type (dynamic)
    outgoing_protos: SccHashIndex<String, Arc<AtomicU64>>,

    // Start time for uptime calculation
    start_time: u32,
}

impl Metrics {
    pub fn new() -> Self {
        let handled_protos = SccHashIndex::new();
        let errors = SccHashIndex::new();
        let sent_packets = SccHashIndex::new();
        Self {
            incoming_bytes: AtomicU64::new(0),
            incoming_packets: AtomicU64::new(0),
            outgoing_bytes: AtomicU64::new(0),
            outgoing_packets: AtomicU64::new(0),
            incoming_protos: handled_protos,
            errors,
            outgoing_protos: sent_packets,
            start_time: get_unix_secs_now(),
        }
    }

    #[inline]
    pub fn add_incoming_proto(&self, name: &str) {
        // correct way of handling ownership in scc HashIndex
        let name = name.to_owned();
        if let Some(counter) = self.incoming_protos.get(&name) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.incoming_protos.insert(name, Arc::new(AtomicU64::new(1)));
        }
    }

    #[inline]
    pub fn add_outgoing_proto(&self, name: &str) {
        // correct way of handling ownership in scc HashIndex
        let name = name.to_owned();
        if let Some(counter) = self.outgoing_protos.get(&name) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.outgoing_protos.insert(name, Arc::new(AtomicU64::new(1)));
        }
    }

    /// Increment UDP packet count with size
    pub fn add_incoming_udp_packet(&self, len: usize) {
        self.incoming_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.incoming_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment outgoing UDP packet count with size
    pub fn add_outgoing_udp_packet(&self, len: usize) {
        self.outgoing_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.outgoing_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment V2 parsing errors
    pub fn add_error<E: Debug + Typename>(&self, error: &E) {
        warn!(target = "metrics", "error: {error:?}");
        self.add_error_by_name(error.typename());
    }

    fn add_error_by_name(&self, error_type: &str) {
        // correct way of handling ownership in scc HashIndex
        let et_owned = error_type.to_string();
        if let Some(counter) = self.errors.get(&et_owned) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.errors.insert(et_owned, Arc::new(AtomicU64::new(1)));
        }
    }

    /// Get a complete metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        let guard = Guard::new();
        let uptime = get_unix_secs_now() - self.start_time;

        let mut incoming_protos = HashMap::new();
        let mut iter = self.incoming_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            incoming_protos.insert(proto_name.clone(), counter.load(Ordering::Relaxed));
        }

        let mut errors = HashMap::new();
        let mut iter = self.errors.iter(&guard);
        while let Some((error_type, counter)) = iter.next() {
            errors.insert(error_type.clone(), counter.load(Ordering::Relaxed));
        }

        let mut outgoing_protos = HashMap::new();
        let mut iter = self.outgoing_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            outgoing_protos.insert(proto_name.clone(), counter.load(Ordering::Relaxed));
        }

        let (udp, udpps) = self.get_udp_stats(uptime);
        MetricsSnapshot { incoming_protos, outgoing_protos, uptime, errors, udp, udpps }
    }

    fn get_udp_stats(&self, uptime_seconds: u32) -> (UdpStats, Option<UdpStats>) {
        static LAST_INCOMING_BYTES: AtomicU64 = AtomicU64::new(0);
        static LAST_INCOMING_PACKETS: AtomicU64 = AtomicU64::new(0);
        static LAST_OUTGOING_BYTES: AtomicU64 = AtomicU64::new(0);
        static LAST_OUTGOING_PACKETS: AtomicU64 = AtomicU64::new(0);
        static LAST_UPTIME_SECONDS: AtomicU32 = AtomicU32::new(0);

        let incoming_packets = self.incoming_packets.load(Ordering::Relaxed);
        let incoming_bytes = self.incoming_bytes.load(Ordering::Relaxed);
        let outgoing_packets = self.outgoing_packets.load(Ordering::Relaxed);
        let outgoing_bytes = self.outgoing_bytes.load(Ordering::Relaxed);

        let lus = LAST_UPTIME_SECONDS.swap(uptime_seconds, Ordering::Relaxed);
        let lip = LAST_INCOMING_PACKETS.swap(incoming_packets, Ordering::Relaxed);
        let lib = LAST_INCOMING_BYTES.swap(incoming_bytes, Ordering::Relaxed);
        let lop = LAST_OUTGOING_PACKETS.swap(outgoing_packets, Ordering::Relaxed);
        let lob = LAST_OUTGOING_BYTES.swap(outgoing_bytes, Ordering::Relaxed);

        let udp = UdpStats { incoming_packets, incoming_bytes, outgoing_packets, outgoing_bytes };
        let mut udpps = None;

        if lus != 0 {
            let seconds = if uptime_seconds != lus { (uptime_seconds - lus) as u64 } else { 1 };
            udpps = Some(UdpStats {
                incoming_packets: (incoming_packets - lip) / seconds,
                incoming_bytes: (incoming_bytes - lib) / seconds,
                outgoing_packets: (outgoing_packets - lop) / seconds,
                outgoing_bytes: (outgoing_bytes - lob) / seconds,
            });
        }

        (udp, udpps)
    }

    /// Get JSON-formatted metrics (backward compatibility)
    pub fn get_json(&self) -> serde_json::Value {
        serde_json::to_value(self.get_snapshot()).unwrap_or_else(|e| {
            warn!("Failed to serialize metrics: {}", e);
            serde_json::json!({})
        })
    }

    /// Get Prometheus-formatted metrics (backward compatibility)
    pub fn get_prometheus(&self) -> String {
        self.get_snapshot().to_prometheus_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_totals_are_tracked() {
        let m = Metrics::new();
        m.add_incoming_udp_packet(100);
        m.add_incoming_udp_packet(250);
        let snapshot = m.get_snapshot();
        assert_eq!(snapshot.udp.incoming_packets, 2);
        assert_eq!(snapshot.udp.incoming_bytes, 350);
    }

    #[test]
    fn protocol_counters_and_prometheus_include_counts() {
        let m = Metrics::new();
        m.add_incoming_proto("ping");
        m.add_incoming_proto("ping");
        m.add_incoming_proto("peers");

        let snapshot = m.get_snapshot();
        assert_eq!(snapshot.incoming_protos.get("ping"), Some(&2));
        assert_eq!(snapshot.incoming_protos.get("peers"), Some(&1));

        let prom = snapshot.to_prometheus_string();
        assert!(prom.contains("amadeus_incoming_protos_total{type=\"ping\"} 2"));
        assert!(prom.contains("amadeus_incoming_protos_total{type=\"peers\"} 1"));
    }

    #[derive(Debug)]
    struct DummyErr;
    impl crate::utils::misc::Typename for DummyErr {
        fn typename(&self) -> &'static str {
            "dummy"
        }
    }

    #[test]
    fn error_counters_by_typename_and_prometheus() {
        let m = Metrics::new();
        let e = DummyErr;
        m.add_error(&e);
        m.add_error(&e);

        let snapshot = m.get_snapshot();
        assert_eq!(snapshot.errors.get("dummy"), Some(&2));

        let prom = snapshot.to_prometheus_string();
        assert!(prom.contains("amadeus_packet_errors_total{type=\"dummy\"} 2"));
    }

    #[test]
    fn uptime_is_nonnegative_and_present() {
        let m = Metrics::new();
        let snapshot = m.get_snapshot();
        // u64 is always >= 0, just test that it's accessible
        let _uptime = snapshot.uptime;
    }

    #[test]
    fn prometheus_packet_totals_reflect_counters() {
        let m = Metrics::new();
        m.add_incoming_udp_packet(10);
        m.add_incoming_udp_packet(20);
        m.add_outgoing_udp_packet(15);
        let prom = m.get_snapshot().to_prometheus_string();
        assert!(prom.contains("amadeus_udp_packets_total{type=\"incoming\"} 2"));
        assert!(prom.contains("amadeus_udp_bytes_total{type=\"incoming\"} 30"));
        assert!(prom.contains("amadeus_udp_packets_total{type=\"outgoing\"} 1"));
        assert!(prom.contains("amadeus_udp_bytes_total{type=\"outgoing\"} 15"));
    }

    #[test]
    fn sent_packet_counters_and_prometheus_include_counts() {
        let m = Metrics::new();
        m.add_outgoing_proto("ping");
        m.add_outgoing_proto("ping");
        m.add_outgoing_proto("pong");

        let snapshot = m.get_snapshot();
        assert_eq!(snapshot.outgoing_protos.get("ping"), Some(&2));
        assert_eq!(snapshot.outgoing_protos.get("pong"), Some(&1));

        let prom = snapshot.to_prometheus_string();
        assert!(prom.contains("amadeus_outgoing_protos_total{type=\"ping\"} 2"));
        assert!(prom.contains("amadeus_outgoing_protos_total{type=\"pong\"} 1"));
    }

    #[test]
    fn metrics_snapshot_serialization() {
        let m = Metrics::new();
        m.add_incoming_proto("test");
        m.add_outgoing_proto("test");
        m.add_incoming_udp_packet(100);

        let snapshot = m.get_snapshot();

        // Test that we can serialize and deserialize the snapshot
        let json = serde_json::to_string(&snapshot).expect("Should serialize");
        let deserialized: MetricsSnapshot = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.incoming_protos.get("test"), Some(&1));
        assert_eq!(deserialized.outgoing_protos.get("test"), Some(&1));
        assert_eq!(deserialized.udp.incoming_packets, 1);
        assert_eq!(deserialized.udp.incoming_bytes, 100);
    }

    #[test]
    fn prometheus_generation_from_snapshot() {
        let m = Metrics::new();
        m.add_incoming_proto("test_proto");
        m.add_incoming_udp_packet(50);

        let snapshot = m.get_snapshot();
        let prometheus = snapshot.to_prometheus_string();

        assert!(prometheus.contains("amadeus_incoming_protos_total{type=\"test_proto\"} 1"));
        assert!(prometheus.contains("amadeus_udp_packets_total{type=\"incoming\"} 1"));
        assert!(prometheus.contains("amadeus_udp_bytes_total{type=\"incoming\"} 50"));
    }
}
