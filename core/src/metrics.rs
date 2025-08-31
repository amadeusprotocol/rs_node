use crate::utils::misc::{Typename, get_unix_secs_now};
use scc::HashIndex as SccHashIndex;
use scc::ebr::Guard;
use serde_json::Value;
use std::collections::HashMap as StdHashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

pub struct Metrics {
    // Total packets counter
    incoming_bytes: AtomicU64,   // Total bytes received
    incoming_packets: AtomicU64, // Total UDP packets received
    outgoing_bytes: AtomicU64,   // Total bytes sent
    outgoing_packets: AtomicU64, // Total UDP packets sent

    // Handled protocol message counters by name (dynamic)
    handled_protos: SccHashIndex<String, Arc<AtomicU64>>,

    // Error counters by type name (dynamic)
    errors: SccHashIndex<String, Arc<AtomicU64>>,

    // Sent packets counter by protocol type (dynamic)
    sent_packets: SccHashIndex<String, Arc<AtomicU64>>,

    // Start time for uptime calculation
    start_time: u64,
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
            handled_protos,
            errors,
            sent_packets,
            start_time: get_unix_secs_now(),
        }
    }

    #[inline]
    pub fn add_handled_proto_by_name(&self, proto_name: &str) {
        // correct way of handling ownership in scc HashIndex
        let pn_owned = proto_name.to_string();
        if let Some(counter) = self.handled_protos.get(&pn_owned) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.handled_protos.insert(pn_owned, Arc::new(AtomicU64::new(1)));
        }
    }

    #[inline]
    pub fn add_sent_packet_by_name(&self, proto_name: &str) {
        // correct way of handling ownership in scc HashIndex
        let pn_owned = proto_name.to_string();
        if let Some(counter) = self.sent_packets.get(&pn_owned) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.sent_packets.insert(pn_owned, Arc::new(AtomicU64::new(1)));
        }
    }

    /// Increment UDP packet count with size
    pub fn add_v2_udp_packet(&self, len: usize) {
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
        warn!(target = "metrics", "v2 error: {error:?}");
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

    /// Get JSON-formatted metrics
    pub fn get_json(&self) -> Value {
        let guard = Guard::new();

        let mut protos = StdHashMap::new();
        let mut iter = self.handled_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            protos.insert(proto_name.clone(), counter.load(Ordering::Relaxed));
        }

        let mut errors = StdHashMap::new();
        let mut iter = self.errors.iter(&guard);
        while let Some((error_type, counter)) = iter.next() {
            errors.insert(error_type.clone(), counter.load(Ordering::Relaxed));
        }

        let mut sent_packets = StdHashMap::new();
        let mut iter = self.sent_packets.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            sent_packets.insert(proto_name.clone(), counter.load(Ordering::Relaxed));
        }

        let uptime_seconds = get_unix_secs_now() - self.start_time;

        serde_json::json!({
            "handled_protos": protos,
            "sent_packets": sent_packets,
            "errors": errors,
            "packets": self.get_packets_json(uptime_seconds),
            "uptime": uptime_seconds
        })
    }

    fn get_packets_json(&self, uptime_seconds: u64) -> serde_json::Value {
        static LAST_INCOMING_BYTES: AtomicU64 = AtomicU64::new(0);
        static LAST_INCOMING_PACKETS: AtomicU64 = AtomicU64::new(0);
        static LAST_OUTGOING_BYTES: AtomicU64 = AtomicU64::new(0);
        static LAST_OUTGOING_PACKETS: AtomicU64 = AtomicU64::new(0);
        static LAST_UPTIME_SECONDS: AtomicU64 = AtomicU64::new(0);

        let incoming_packets = self.incoming_packets.load(Ordering::Relaxed);
        let incoming_bytes = self.incoming_bytes.load(Ordering::Relaxed);
        let outgoing_packets = self.outgoing_packets.load(Ordering::Relaxed);
        let outgoing_bytes = self.outgoing_bytes.load(Ordering::Relaxed);

        let lus = LAST_UPTIME_SECONDS.swap(uptime_seconds, Ordering::Relaxed);
        let lip = LAST_INCOMING_PACKETS.swap(incoming_packets, Ordering::Relaxed);
        let lib = LAST_INCOMING_BYTES.swap(incoming_bytes, Ordering::Relaxed);
        let lop = LAST_OUTGOING_PACKETS.swap(outgoing_packets, Ordering::Relaxed);
        let lob = LAST_OUTGOING_BYTES.swap(outgoing_bytes, Ordering::Relaxed);

        if lus == 0 {
            return serde_json::json!({
                "total_incoming_packets": incoming_packets,
                "total_incoming_bytes": incoming_bytes,
                "total_outgoing_packets": outgoing_packets,
                "total_outgoing_bytes": outgoing_bytes
            });
        }

        let seconds = if uptime_seconds != lus { uptime_seconds - lus } else { 1 };
        let in_packets = incoming_packets - lip;
        let in_bytes = incoming_bytes - lib;
        let out_packets = outgoing_packets - lop;
        let out_bytes = outgoing_bytes - lob;

        serde_json::json!({
            "total_incoming_packets": incoming_packets,
            "total_incoming_bytes": incoming_bytes,
            "total_outgoing_packets": outgoing_packets,
            "total_outgoing_bytes": outgoing_bytes,
            "incoming_packets_per_second": in_packets / seconds,
            "incoming_bytes_per_second": in_bytes / seconds,
            "outgoing_packets_per_second": out_packets / seconds,
            "outgoing_bytes_per_second": out_bytes / seconds,
        })
    }

    /// Prometheus-formatted metrics string
    pub fn get_prometheus(&self) -> String {
        let packets = format!(
            r#"
# HELP amadeus_udp_packets_total Total number of UDP packets
# TYPE amadeus_udp_packets_total counter
amadeus_udp_packets_incoming_total {}
amadeus_udp_packets_outgoing_total {}

# HELP amadeus_udp_bytes_total Total number of UDP bytes
# TYPE amadeus_udp_bytes_total counter
amadeus_udp_bytes_incoming_total {}
amadeus_udp_bytes_outgoing_total {}

# HELP amadeus_uptime_seconds Process uptime in seconds
# TYPE amadeus_uptime_seconds gauge
amadeus_uptime_seconds {}"#,
            self.incoming_packets.load(Ordering::Relaxed),
            self.outgoing_packets.load(Ordering::Relaxed),
            self.incoming_bytes.load(Ordering::Relaxed),
            self.outgoing_bytes.load(Ordering::Relaxed),
            get_unix_secs_now() - self.start_time
        );

        let mut protos = Vec::new();
        protos.push("\n\n# HELP amadeus_protocol_messages_total Total number of proto messages handled by type".into());
        protos.push("# TYPE amadeus_protocol_messages_total counter".into());
        let guard = Guard::new();
        let mut iter = self.handled_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            let count = counter.load(Ordering::Relaxed);
            protos.push(format!("amadeus_protocol_messages_total{{type=\"{}\"}} {}", proto_name, count));
        }

        let mut sent_packets = Vec::new();
        sent_packets.push("\n\n# HELP amadeus_sent_packets_total Total number of packets sent by protocol type".into());
        sent_packets.push("# TYPE amadeus_sent_packets_total counter".into());
        let mut iter = self.sent_packets.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            let count = counter.load(Ordering::Relaxed);
            sent_packets.push(format!("amadeus_sent_packets_total{{type=\"{}\"}} {}", proto_name, count));
        }

        let mut errors = Vec::new();
        errors.push("\n\n# HELP amadeus_packet_errors_total Total number of packet processing errors by type".into());
        errors.push("# TYPE amadeus_packet_errors_total counter".into());
        let mut iter = self.errors.iter(&guard);
        while let Some((error_type, counter)) = iter.next() {
            let count = counter.load(Ordering::Relaxed);
            errors.push(format!("amadeus_packet_errors_total{{type=\"{}\"}} {}", error_type, count));
        }

        format!("{}{}{}{}", packets, protos.join("\n"), sent_packets.join("\n"), errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_totals_are_tracked() {
        let m = Metrics::new();
        m.add_v2_udp_packet(100);
        m.add_v2_udp_packet(250);
        let j = m.get_json();
        let packets = j.get("packets").expect("packets").as_object().unwrap();
        assert_eq!(packets.get("total_incoming_packets").unwrap().as_u64().unwrap(), 2);
        assert_eq!(packets.get("total_incoming_bytes").unwrap().as_u64().unwrap(), 350);
    }

    #[test]
    fn protocol_counters_and_prometheus_include_counts() {
        let m = Metrics::new();
        m.add_handled_proto_by_name("ping");
        m.add_handled_proto_by_name("ping");
        m.add_handled_proto_by_name("peers");

        let j = m.get_json();
        let protos = j.get("handled_protos").unwrap().as_object().unwrap();
        assert_eq!(protos.get("ping").unwrap().as_u64().unwrap(), 2);
        assert_eq!(protos.get("peers").unwrap().as_u64().unwrap(), 1);

        let prom = m.get_prometheus();
        assert!(prom.contains("amadeus_protocol_messages_total{type=\"ping\"} 2"));
        assert!(prom.contains("amadeus_protocol_messages_total{type=\"peers\"} 1"));
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

        let j = m.get_json();
        let errs = j.get("errors").unwrap().as_object().unwrap();
        assert_eq!(errs.get("dummy").unwrap().as_u64().unwrap(), 2);

        let prom = m.get_prometheus();
        assert!(prom.contains("amadeus_packet_errors_total{type=\"dummy\"} 2"));
    }

    #[test]
    fn uptime_is_nonnegative_and_present() {
        let m = Metrics::new();
        let j = m.get_json();
        let uptime_val = j.get("uptime").unwrap();
        assert!(uptime_val.is_u64());
    }

    #[test]
    fn prometheus_packet_totals_reflect_counters() {
        let m = Metrics::new();
        m.add_v2_udp_packet(10);
        m.add_v2_udp_packet(20);
        m.add_outgoing_udp_packet(15);
        let prom = m.get_prometheus();
        assert!(prom.contains("amadeus_udp_packets_incoming_total 2"));
        assert!(prom.contains("amadeus_udp_bytes_incoming_total 30"));
        assert!(prom.contains("amadeus_udp_packets_outgoing_total 1"));
        assert!(prom.contains("amadeus_udp_bytes_outgoing_total 15"));
    }

    #[test]
    fn sent_packet_counters_and_prometheus_include_counts() {
        let m = Metrics::new();
        m.add_sent_packet_by_name("ping");
        m.add_sent_packet_by_name("ping");
        m.add_sent_packet_by_name("pong");

        let j = m.get_json();
        let sent = j.get("sent_packets").unwrap().as_object().unwrap();
        assert_eq!(sent.get("ping").unwrap().as_u64().unwrap(), 2);
        assert_eq!(sent.get("pong").unwrap().as_u64().unwrap(), 1);

        let prom = m.get_prometheus();
        assert!(prom.contains("amadeus_sent_packets_total{type=\"ping\"} 2"));
        assert!(prom.contains("amadeus_sent_packets_total{type=\"pong\"} 1"));
    }
}
