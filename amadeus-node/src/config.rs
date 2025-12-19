/// The only file where reading environment variables is allowed
/// Basically, the config for the whole the core library
use crate::node::anr::Anr;
use crate::utils::bls12_381;
pub use crate::utils::bls12_381::generate_sk as gen_sk;
use crate::utils::ip_resolver::resolve_public_ipv4;
use crate::utils::version::Ver;
use crate::utils::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

// constants from elixir config/config.exs
pub const ENTRY_SIZE: usize = 524288; // 512 KiB
pub const TX_SIZE: usize = 393216; // 384 KiB  
pub const ATTESTATION_SIZE: usize = 512;
pub const QUORUM: usize = 3; // quorum size for AMA
pub const QUORUM_SINGLE: usize = 1; // quorum size for single shard
pub const CLEANUP_PERIOD_MILLIS: u64 = 3000; // how often node does the cleanup
pub const ANR_PERIOD_MILLIS: u64 = 3000; // how often node checks ANR status
pub const BROADCAST_PERIOD_MILLIS: u64 = 500; // how often node broadcasts pings
pub const AUTOUPDATE_PERIOD_MILLIS: u64 = 1000; // how often node checks for updates
pub const CONSENSUS_PERIOD_MILLIS: u64 = 100; // how often node runs consensus
pub const CATCHUP_PERIOD_MILLIS: u64 = 1000; // how often node checks for entry gaps

pub const VERSION: Ver = parse_version();

/// IMPORTANT for compatibility
pub const BINCODE_CONFIG: bincode::config::Configuration<
    bincode::config::BigEndian,
    bincode::config::Fixint,
    bincode::config::NoLimit,
> = bincode::config::standard()
    .with_fixed_int_encoding() // fixed ints
    .with_big_endian() // network byte order
    .with_no_limit(); // no size cap

const fn parse_version() -> Ver {
    const S: &str = env!("CRATE_VERSION");
    let bytes = S.as_bytes();
    let mut out = [0u8; 3];
    let mut acc = 0u8;
    let mut part = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            out[part] = acc;
            part += 1;
            acc = 0;
        } else {
            acc = acc * 10 + (b - b'0');
        }
        i += 1;
    }
    out[part] = acc;
    Ver::from_bytes(out)
}

pub const SEED_NODES: &[&str] = &["72.9.144.110", "167.235.169.185", "37.27.238.30"];

// seed anr from elixir config/config.exs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedANR {
    pub ip4: String,
    pub port: u16,
    pub version: Ver,
    pub signature: Vec<u8>,
    pub pop: Signature,
    pub ts: u32,
    pub pk: PublicKey,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] std::net::AddrParseError),
    #[error(transparent)]
    B58(#[from] bs58::decode::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error("invalid sk length: {0}, expected 64")]
    InvalidSkLength(usize),
    #[error(transparent)]
    Anr(#[from] crate::node::anr::Error),
}

#[derive(Clone)]
pub struct Config {
    // filesystem paths
    pub work_folder: String,

    // version info
    pub version: Ver,

    // network configuration
    pub offline: bool,
    pub http_ipv4: Ipv4Addr,
    pub http_port: u16,
    pub udp_ipv4: Ipv4Addr,
    pub udp_port: u16,
    pub public_ipv4: Option<String>,

    // node discovery
    pub seed_ips: Vec<Ipv4Addr>,
    pub seed_anrs: Vec<SeedANR>,
    pub other_nodes: Vec<String>,
    pub trust_factor: f64,
    pub max_peers: usize,

    // trainer keys
    pub trainer_sk: [u8; 64],
    pub trainer_pk: PublicKey,
    pub trainer_pk_b58: String,
    pub trainer_pop: Vec<u8>,

    // runtime settings
    pub archival_node: bool,
    pub autoupdate: bool,
    pub computor_type: Option<ComputorType>,
    pub snapshot_height: u64,

    // anr configuration
    pub anr: Option<Anr>,
    pub anr_name: Option<String>,
    pub anr_desc: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComputorType {
    Trainer,
    Default,
}

impl Config {
    /// Generates pk from self.sk
    pub fn get_pk(&self) -> PublicKey {
        self.trainer_pk
    }

    pub fn get_sk(&self) -> [u8; 64] {
        self.trainer_sk
    }

    pub fn get_pop(&self) -> Vec<u8> {
        self.trainer_pop.clone()
    }

    /// Returns root work folder path
    pub fn get_root(&self) -> &str {
        &self.work_folder
    }

    pub fn get_ver(&self) -> Ver {
        self.version
    }

    pub fn get_ver_3b(&self) -> (u8, u8, u8) {
        (self.version.major(), self.version.minor(), self.version.patch())
    }

    pub fn get_public_ipv4(&self) -> Ipv4Addr {
        self.public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1))
    }

    pub fn get_udp_port(&self) -> u16 {
        self.udp_port
    }

    /// Create Config instance matching elixir config/runtime.exs
    pub async fn from_fs(root: Option<&str>, sk: Option<&str>) -> Result<Self, Error> {
        // work folder from env or default
        let work_folder = std::env::var("WORKFOLDER").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            format!("{}/.amadeusd-rs", home)
        });

        // override with provided root if given
        let work_folder = root.unwrap_or(&work_folder).to_string();
        fs::create_dir_all(&work_folder).await?;

        let version = VERSION;

        // network configuration from env
        let offline = std::env::var("OFFLINE").is_ok();
        let http_ipv4 = std::env::var("HTTP_IPV4")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
            .parse()
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let http_port = std::env::var("HTTP_PORT").unwrap_or_else(|_| "80".to_string()).parse().unwrap_or(80);
        let udp_ipv4 = std::env::var("UDP_IPV4")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
            .parse()
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let udp_port = 36969;

        // node discovery
        let seed_ips = SEED_NODES.iter().map(|s| s.parse()).collect::<Result<Vec<Ipv4Addr>, _>>()?;
        let other_nodes =
            std::env::var("OTHERNODES").map(|s| s.split(',').map(String::from).collect()).unwrap_or_else(|_| vec![]);
        let trust_factor = std::env::var("TRUSTFACTOR").ok().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.8);
        let max_peers = std::env::var("MAX_PEERS").unwrap_or_else(|_| "300".to_string()).parse().unwrap_or(300);

        // verify time sync (warning only)
        if !verify_time_sync() {
            warn!("time not synced OR systemd-ntp client not found (can cause sync errors)");
        }

        // load or generate trainer keys
        let default_sk_path = format!("{}/sk", work_folder);
        let (trainer_sk, trainer_pk, trainer_pk_b58) = if let Some(path) = sk {
            let sk = read_sk(path).await?;
            let pk = get_pk(&sk);
            (sk, pk, bs58::encode(pk).into_string())
        } else if let Ok(sk) = read_sk(&default_sk_path).await {
            let pk = get_pk(&sk);
            (sk, pk, bs58::encode(pk).into_string())
        } else {
            debug!("no sk (BLS12-381) found, generating new trainer keys");
            let sk = gen_sk();
            let pk = get_pk(&sk);
            let pk_b58 = bs58::encode(pk).into_string();
            info!("generated random sk at {default_sk_path}, pk {pk_b58}");
            write_sk(&default_sk_path, sk).await?;
            (sk, pk, pk_b58)
        };

        // generate proof of possession
        let trainer_pop = bls12_381::sign(&trainer_sk, trainer_pk.as_ref(), crate::consensus::DST_POP)
            .map(|sig| sig.to_vec())
            .unwrap_or_else(|_| vec![0u8; 96]);

        // runtime settings from env
        let archival_node = matches!(std::env::var("ARCHIVALNODE").as_deref(), Ok("true") | Ok("y") | Ok("yes"));
        let autoupdate = matches!(std::env::var("AUTOUPDATE").as_deref(), Ok("true") | Ok("y") | Ok("yes"));
        let computor_type = match std::env::var("COMPUTOR").as_deref() {
            Ok("trainer") => Some(ComputorType::Trainer),
            Ok(_) => Some(ComputorType::Default),
            Err(_) => None,
        };
        let snapshot_height =
            std::env::var("SNAPSHOT_HEIGHT").unwrap_or_else(|_| "24875547".to_string()).parse().unwrap_or(24875547);

        // get public IP
        let my_ip = match std::env::var("PUBLIC_UDP_IPV4").ok().and_then(|i| i.parse::<Ipv4Addr>().ok()) {
            Some(ip) => Some(ip),
            None => resolve_public_ipv4().await, //.unwrap_or(Ipv4Addr::new(127, 0, 0, 1)),
        };

        let ver = version;
        let public_ipv4 = my_ip.map(|ip| ip.to_string());

        // anr configuration
        let anr_name = std::env::var("ANR_NAME").ok();
        let anr_desc = std::env::var("ANR_DESC").ok();

        let anr = my_ip.and_then(|ip| {
            Anr::build_with_name_desc(
                &trainer_sk,
                &trainer_pk,
                &trainer_pop,
                ip,
                ver,
                anr_name.clone(),
                anr_desc.clone(),
            )
            .ok()
        });

        let seed_anrs = vec![
            SeedANR {
                ip4: "72.9.144.110".into(),
                port: 36969,
                version: "1.2.5".try_into().unwrap(),
                signature: vec![
                    132, 66, 55, 44, 126, 255, 89, 218, 33, 243, 214, 44, 103, 181, 166, 16, 54, 195, 44, 159, 66, 87,
                    162, 103, 240, 217, 235, 201, 120, 234, 207, 126, 31, 24, 228, 115, 202, 68, 85, 167, 97, 101, 110,
                    201, 220, 161, 239, 95, 15, 174, 251, 185, 62, 16, 69, 231, 99, 94, 189, 94, 210, 122, 150, 220,
                    226, 218, 207, 108, 242, 168, 189, 252, 146, 129, 113, 239, 53, 211, 69, 92, 115, 218, 40, 15, 104,
                    220, 235, 59, 235, 8, 177, 105, 120, 225, 12, 87,
                ],
                pop: Signature::from([
                    182, 42, 150, 214, 42, 240, 210, 215, 0, 106, 181, 96, 198, 75, 222, 86, 45, 241, 58, 230, 66, 56,
                    10, 49, 217, 53, 39, 100, 18, 197, 159, 153, 68, 220, 234, 164, 6, 9, 3, 228, 234, 209, 151, 233,
                    122, 209, 101, 73, 16, 190, 135, 172, 85, 106, 80, 99, 225, 214, 141, 245, 66, 170, 177, 163, 247,
                    93, 243, 234, 184, 145, 167, 202, 181, 114, 186, 113, 112, 113, 108, 84, 135, 24, 62, 242, 142,
                    248, 159, 124, 117, 85, 190, 43, 177, 212, 18, 24,
                ]),
                ts: 1763051924,
                pk: PublicKey::from([
                    169, 232, 30, 216, 200, 234, 174, 189, 141, 213, 58, 136, 157, 140, 90, 134, 18, 171, 115, 48, 39,
                    90, 93, 57, 4, 62, 149, 32, 14, 124, 27, 102, 240, 220, 0, 197, 48, 126, 134, 122, 85, 169, 173,
                    158, 122, 228, 185, 240,
                ]),
            },
            SeedANR {
                ip4: "167.235.169.185".into(),
                port: 36969,
                version: "1.2.5".try_into().unwrap(),
                signature: vec![
                    128, 163, 49, 163, 123, 191, 81, 52, 48, 69, 65, 212, 233, 85, 88, 167, 138, 156, 204, 105, 91,
                    231, 234, 219, 129, 161, 5, 226, 136, 179, 43, 192, 136, 224, 78, 114, 134, 157, 142, 36, 236, 10,
                    83, 4, 102, 209, 48, 133, 0, 116, 212, 250, 22, 218, 156, 26, 50, 86, 197, 56, 110, 252, 252, 108,
                    202, 58, 218, 181, 30, 213, 227, 46, 175, 227, 45, 174, 162, 33, 160, 113, 165, 114, 115, 232, 207,
                    65, 111, 11, 213, 110, 195, 70, 197, 199, 176, 241,
                ],
                pop: Signature::from([
                    164, 246, 242, 104, 121, 244, 113, 37, 125, 250, 253, 128, 164, 91, 172, 179, 127, 196, 28, 189,
                    170, 239, 154, 195, 216, 36, 42, 27, 69, 132, 140, 126, 88, 213, 175, 124, 0, 109, 83, 10, 90, 12,
                    56, 188, 226, 219, 163, 219, 6, 28, 138, 155, 129, 47, 145, 171, 20, 95, 100, 57, 188, 175, 139,
                    53, 129, 60, 97, 54, 239, 1, 154, 113, 121, 134, 234, 154, 63, 48, 187, 88, 153, 84, 159, 97, 129,
                    241, 120, 192, 107, 55, 45, 250, 208, 196, 44, 141,
                ]),
                ts: 1763065634,
                pk: PublicKey::from([
                    176, 120, 75, 148, 69, 45, 127, 232, 195, 254, 164, 173, 136, 138, 157, 97, 246, 81, 114, 66, 48,
                    199, 162, 230, 152, 219, 207, 224, 18, 246, 194, 150, 228, 105, 126, 41, 68, 36, 246, 51, 135, 216,
                    105, 117, 245, 98, 93, 140,
                ]),
            },
            SeedANR {
                ip4: "37.27.238.30".into(),
                port: 36969,
                version: "1.2.5".try_into().unwrap(),
                signature: vec![
                    142, 128, 166, 98, 166, 146, 49, 71, 166, 160, 208, 182, 120, 22, 114, 79, 95, 23, 30, 33, 120, 68,
                    246, 221, 77, 117, 120, 68, 108, 2, 103, 47, 105, 210, 24, 12, 30, 153, 249, 57, 20, 188, 253, 203,
                    90, 37, 214, 84, 9, 155, 80, 94, 127, 0, 67, 16, 11, 17, 24, 86, 230, 23, 63, 13, 39, 139, 63, 123,
                    5, 83, 154, 38, 183, 44, 1, 66, 112, 7, 53, 155, 129, 58, 239, 68, 155, 115, 239, 241, 255, 65, 56,
                    0, 110, 110, 137, 27,
                ],
                pop: Signature::from([
                    181, 170, 103, 46, 138, 14, 103, 212, 122, 113, 28, 78, 228, 170, 19, 202, 108, 149, 207, 132, 49,
                    208, 221, 32, 121, 229, 5, 95, 72, 120, 73, 47, 230, 70, 155, 89, 98, 194, 196, 206, 230, 63, 49,
                    205, 160, 135, 90, 246, 7, 93, 79, 237, 127, 111, 189, 136, 122, 225, 135, 54, 45, 95, 36, 186,
                    211, 155, 67, 24, 86, 151, 91, 190, 20, 72, 145, 77, 138, 55, 22, 15, 100, 61, 140, 137, 93, 55,
                    19, 5, 226, 106, 30, 134, 74, 55, 193, 163,
                ]),
                ts: 1763066818,
                pk: PublicKey::from([
                    149, 216, 55, 255, 29, 8, 239, 251, 139, 112, 30, 29, 199, 57, 90, 67, 198, 220, 101, 18, 228, 100,
                    100, 241, 43, 213, 221, 230, 253, 58, 231, 1, 102, 166, 54, 66, 245, 148, 140, 44, 78, 56, 84, 12,
                    222, 205, 57, 210,
                ]),
            },
        ];

        Ok(Self {
            work_folder,
            version,
            offline,
            http_ipv4,
            http_port,
            udp_ipv4,
            udp_port,
            public_ipv4,
            seed_ips,
            seed_anrs,
            other_nodes,
            trust_factor,
            max_peers,
            trainer_sk,
            trainer_pk,
            trainer_pk_b58,
            trainer_pop,
            archival_node,
            autoupdate,
            computor_type,
            snapshot_height,
            anr,
            anr_name,
            anr_desc,
        })
    }

    /// Get public IP asynchronously if not already set
    pub async fn ensure_public_ip(&mut self) {
        if self.public_ipv4.is_none() {
            self.public_ipv4 = crate::utils::ip_resolver::resolve_public_ipv4_string().await;
        }
    }

    pub fn new_daemonless(sk: [u8; 64]) -> Self {
        let pk = get_pk(&sk);
        let pk_b58 = bs58::encode(pk).into_string();
        let pop = bls12_381::sign(&sk, pk.as_ref(), crate::consensus::DST_POP)
            .map(|sig| sig.to_vec())
            .unwrap_or_else(|_| vec![0u8; 96]);
        let seed_ips = SEED_NODES.iter().map(|s| s.parse()).collect::<Result<Vec<Ipv4Addr>, _>>().unwrap_or_default();

        Self {
            work_folder: ".amadeusd-rs".to_string(),
            version: VERSION,
            offline: false,
            http_ipv4: Ipv4Addr::new(0, 0, 0, 0),
            http_port: 80,
            udp_ipv4: Ipv4Addr::new(0, 0, 0, 0),
            udp_port: 36969,
            public_ipv4: None,
            seed_ips,
            seed_anrs: vec![],
            other_nodes: vec![],
            trust_factor: 0.8,
            max_peers: 300,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: pk_b58,
            trainer_pop: pop,
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 24875547,
            anr: None,
            anr_name: None,
            anr_desc: None,
        }
    }
}

pub fn get_pk(sk: &[u8; 64]) -> PublicKey {
    bls12_381::get_public_key(sk).expect("key generation should not fail with proper key material")
}

pub async fn write_sk(path: impl AsRef<Path>, sk: [u8; 64]) -> Result<(), Error> {
    let sk_b58 = bs58::encode(sk).into_string();
    fs::write(path, sk_b58).await.map_err(Into::into)
}

pub async fn read_sk(path: impl AsRef<Path>) -> Result<[u8; 64], Error> {
    let sk_bs58 = fs::read_to_string(path).await?;
    let sk_vec = bs58::decode(sk_bs58.trim()).into_vec()?;
    sk_vec.try_into().map_err(|v: Vec<u8>| Error::InvalidSkLength(v.len()))
}

/// Verify time sync using systemd-timesyncd
fn verify_time_sync() -> bool {
    use std::process::Command;

    // try to check systemd-timesyncd status like elixir
    match Command::new("timedatectl").arg("status").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // check if ntp is synchronized
            stdout.contains("System clock synchronized: yes") || stdout.contains("NTP synchronized: yes")
        }
        Err(_) => {
            // if timedatectl is not available, assume time is ok
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name_of_val;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Guard that creates a per-test directory under /tmp and deletes it on drop.
    struct TmpTestDir {
        path: PathBuf,
    }

    impl TmpTestDir {
        /// Create a tmp directory named "/tmp/<fully-qualified-test-path><seconds-since-epoch>".
        /// Pass a reference to the test function item, e.g., `TmpTestDir::for_test(&my_test_fn)`.
        fn for_test<F: ?Sized>(f: &F) -> std::io::Result<Self> {
            let fq = type_name_of_val(f);
            let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let dir_name = format!("{}{}", fq, secs);
            let path = std::path::Path::new("/tmp").join(dir_name);
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        /// Convenience to get &str path.
        fn to_str(&self) -> &str {
            self.path.to_str().unwrap_or("")
        }
    }

    impl Drop for TmpTestDir {
        fn drop(&mut self) {
            // best-effort cleanup
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn test_config_from_env() {
        // per-test tmp dir
        let tmp = TmpTestDir::for_test(&test_config_from_env).unwrap();
        // set up test environment
        unsafe {
            std::env::set_var("WORKFOLDER", tmp.to_str());
            std::env::set_var("HTTP_PORT", "8080");
            std::env::set_var("OTHERNODES", "192.168.1.1,192.168.1.2");
            std::env::set_var("TRUSTFACTOR", "0.9");
            std::env::set_var("MAX_PEERS", "500");
            std::env::set_var("ARCHIVALNODE", "true");
            std::env::set_var("AUTOUPDATE", "yes");
            std::env::set_var("COMPUTOR", "trainer");
            std::env::set_var("SNAPSHOT_HEIGHT", "12345678");
            std::env::set_var("ANR_NAME", "TestNode");
            std::env::set_var("ANR_DESC", "Test Description");
        }

        let config = Config::from_fs(Some(tmp.to_str()), None).await.unwrap();

        // verify filesystem paths from test setup
        assert_eq!(config.work_folder, tmp.to_str());

        // verify network configuration from env
        assert_eq!(config.http_port, 8080);
        assert_eq!(config.other_nodes, vec!["192.168.1.1", "192.168.1.2"]);
        assert_eq!(config.trust_factor, 0.9);
        assert_eq!(config.max_peers, 500);

        // verify generated trainer keys exist
        assert_eq!(config.trainer_sk.len(), 64);
        assert_eq!(config.trainer_pk.len(), 48);
        assert!(!config.trainer_pk_b58.is_empty());
        assert_eq!(config.trainer_pop.len(), 96);

        // verify runtime settings from env
        assert!(config.archival_node);
        assert!(config.autoupdate);
        assert_eq!(config.computor_type, Some(ComputorType::Trainer));
        assert_eq!(config.snapshot_height, 12345678);

        // verify anr configuration from env
        assert_eq!(config.anr_name, Some("TestNode".to_string()));
        assert_eq!(config.anr_desc, Some("Test Description".to_string()));
    }

    #[tokio::test]
    async fn test_config_from_sk() {
        let sk = [42u8; 64];
        let config = Config::new_daemonless(sk);

        // verify the provided sk is used
        assert_eq!(config.trainer_sk, sk);

        // verify keys are generated correctly
        assert_eq!(config.trainer_pk.len(), 48);
        assert!(!config.trainer_pk_b58.is_empty());
        assert_eq!(config.trainer_pop.len(), 96);
    }

    #[tokio::test]
    async fn test_config_env_parsing() {
        // per-test tmp dir
        let tmp = TmpTestDir::for_test(&test_config_env_parsing).unwrap();
        // explicitly set and verify computor type parsing to avoid env races
        unsafe {
            std::env::set_var("COMPUTOR", "trainer");
        }
        let config = Config::from_fs(Some(tmp.to_str()), None).await.unwrap();
        assert_eq!(config.computor_type, Some(ComputorType::Trainer));

        unsafe {
            std::env::set_var("COMPUTOR", "default");
        }
        let config = Config::from_fs(Some(tmp.to_str()), None).await.unwrap();
        assert_eq!(config.computor_type, Some(ComputorType::Default));
    }

    #[tokio::test]
    async fn test_config_version_methods() {
        // per-test tmp dir
        let tmp = TmpTestDir::for_test(&test_config_version_methods).unwrap();
        let config = Config::from_fs(Some(tmp.to_str()), None).await.unwrap();

        // Test that get_ver() returns a string and get_ver_3b() returns consistent tuple
        let version_str = config.get_ver().to_string();
        let version_3b = config.get_ver_3b();

        // Parse the string version and compare with tuple
        let parts: Vec<&str> = version_str.split('.').collect();
        assert_eq!(parts.len(), 3, "Version string should have 3 parts");

        let expected_major = parts[0].parse::<u8>().unwrap();
        let expected_minor = parts[1].parse::<u8>().unwrap();
        let expected_patch = parts[2].parse::<u8>().unwrap();

        assert_eq!(version_3b.0, expected_major);
        assert_eq!(version_3b.1, expected_minor);
        assert_eq!(version_3b.2, expected_patch);

        // Verify it matches the version field directly
        assert_eq!(version_3b, (config.version.major(), config.version.minor(), config.version.patch()));
    }

    #[test]
    fn create_keypair() {
        let sk = gen_sk();
        let pk = get_pk(&sk);
        let pk_b58 = bs58::encode(pk).into_string();
        let sk_b58 = bs58::encode(sk).into_string();
        println!("generated random sk at {sk_b58}, pk {pk_b58}");
    }
}
