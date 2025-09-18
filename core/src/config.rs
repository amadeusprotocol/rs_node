/// The only file where reading environment variables is allowed
/// Basically, the config for the whole the core library
use crate::node::anr::Anr;
use crate::utils::bls12_381;
pub use crate::utils::bls12_381::generate_sk as gen_sk;
use crate::utils::ip_resolver::resolve_public_ipv4;
use crate::utils::version::Ver;
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
pub const CLEANUP_PERIOD_SECS: u64 = 8; // how often node does the cleanup
pub const HANDSHAKE_PERIOD_SECS: u64 = 1; // how often node checks ANR status
pub const BROADCAST_PERIOD_SECS: u64 = 1; // how often node broadcasts pings

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

pub const SEED_NODES: &[&str] = &[
    "72.9.144.110", "72.9.146.98", "46.17.96.23", "72.9.146.95", "72.9.146.75",
    "72.9.146.91", "72.9.146.99", "72.9.146.71", "72.9.146.86", "72.9.146.89",
    "72.9.146.93", "72.9.146.81", "72.9.146.102", "72.9.146.114", "46.17.103.22",
    "72.9.146.106", "72.9.146.100", "72.9.146.111", "37.27.238.30", "72.9.146.109",
    "156.67.62.246", "90.11.201.149", "139.60.162.57", "80.209.242.171",
    "67.222.138.150", "67.222.138.149", "185.130.227.22", "66.248.204.226",
    "152.114.194.195", "194.180.188.146"
];

// seed anr from elixir config/config.exs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedANR {
    pub ip4: String,
    pub port: u16,
    pub version: Ver,
    pub signature: Vec<u8>,
    pub ts: u32,
    pub pk: Vec<u8>,
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
    #[error("root directory is not set")]
    RootNotSet,
    #[error("time not synced")]
    TimeNotSynced,
    #[error(transparent)]
    AnrError(#[from] crate::node::anr::Error),
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
    pub trainer_pk: [u8; 48],
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
    pub fn get_pk(&self) -> [u8; 48] {
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
            format!("{}/.cache/rs_amadeusd", home)
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
        let trainer_pop = bls12_381::sign(&trainer_sk, &trainer_pk, crate::consensus::DST_POP)
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
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.144.110".to_string(),
                pk: vec![
                    169, 232, 30, 216, 200, 234, 174, 189, 141, 213, 58, 136, 157, 140, 90, 134, 18, 171, 115, 48, 39,
                    90, 93, 57, 4, 62, 149, 32, 14, 124, 27, 102, 240, 220, 0, 197, 48, 126, 134, 122, 85, 169, 173,
                    158, 122, 228, 185, 240,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.98".to_string(),
                pk: vec![
                    138, 226, 76, 96, 86, 199, 13, 13, 21, 183, 97, 215, 5, 151, 122, 121, 17, 253, 60, 23, 185, 223,
                    58, 87, 254, 17, 130, 252, 240, 141, 228, 172, 113, 234, 121, 62, 236, 63, 63, 40, 255, 192, 84,
                    218, 116, 161, 51, 249,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "46.17.96.23".to_string(),
                pk: vec![
                    164, 38, 75, 17, 209, 85, 21, 182, 15, 147, 128, 170, 220, 167, 171, 197, 114, 205, 84, 237, 199,
                    214, 84, 247, 16, 26, 43, 93, 28, 100, 17, 113, 141, 204, 136, 141, 167, 197, 55, 137, 115, 122,
                    250, 210, 16, 53, 6, 15,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.95".to_string(),
                pk: vec![
                    142, 14, 77, 126, 145, 118, 121, 22, 108, 41, 165, 91, 65, 4, 51, 220, 15, 233, 150, 59, 3, 88, 38,
                    162, 225, 101, 60, 24, 64, 251, 204, 35, 213, 76, 224, 251, 228, 199, 130, 122, 221, 93, 112, 227,
                    44, 245, 220, 252,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.75".to_string(),
                pk: vec![
                    176, 177, 87, 42, 183, 77, 16, 251, 144, 207, 206, 22, 138, 36, 178, 117, 13, 148, 248, 252, 100,
                    79, 68, 31, 67, 188, 161, 240, 211, 177, 235, 103, 208, 130, 229, 207, 230, 80, 121, 19, 170, 49,
                    253, 31, 204, 161, 164, 31,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.91".to_string(),
                pk: vec![
                    185, 169, 90, 129, 100, 169, 59, 143, 188, 121, 129, 167, 95, 254, 181, 136, 150, 200, 182, 87, 52,
                    5, 225, 25, 45, 214, 59, 243, 112, 150, 49, 38, 115, 102, 108, 66, 214, 148, 94, 34, 156, 142, 208,
                    89, 47, 228, 48, 88,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.99".to_string(),
                pk: vec![
                    162, 202, 8, 40, 213, 212, 220, 108, 76, 203, 235, 135, 227, 87, 141, 158, 208, 200, 106, 166, 18,
                    182, 186, 158, 4, 236, 78, 105, 68, 72, 185, 16, 8, 80, 230, 81, 184, 233, 55, 83, 118, 251, 111,
                    152, 237, 228, 7, 141,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.71".to_string(),
                pk: vec![
                    182, 11, 129, 168, 164, 248, 152, 144, 119, 38, 210, 108, 236, 67, 188, 95, 165, 215, 207, 254,
                    150, 106, 166, 129, 16, 35, 207, 8, 190, 155, 252, 241, 115, 169, 40, 59, 124, 152, 135, 10, 235,
                    135, 188, 42, 253, 139, 245, 98,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.86".to_string(),
                pk: vec![
                    148, 215, 52, 131, 117, 20, 215, 168, 194, 199, 251, 11, 16, 235, 4, 220, 31, 128, 60, 174, 242,
                    134, 71, 97, 145, 121, 35, 130, 192, 107, 104, 2, 149, 86, 237, 117, 37, 176, 18, 116, 44, 225,
                    186, 162, 32, 221, 94, 160,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.89".to_string(),
                pk: vec![
                    151, 228, 47, 216, 215, 238, 127, 192, 13, 253, 95, 174, 69, 110, 62, 67, 240, 221, 91, 163, 123,
                    35, 31, 169, 239, 254, 166, 231, 28, 40, 161, 54, 15, 87, 166, 255, 253, 208, 178, 88, 189, 83,
                    207, 194, 19, 27, 189, 40,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.93".to_string(),
                pk: vec![
                    135, 29, 46, 178, 120, 170, 142, 91, 183, 19, 222, 92, 115, 30, 232, 238, 243, 199, 57, 70, 185,
                    232, 237, 177, 59, 115, 24, 244, 87, 143, 149, 252, 128, 245, 61, 102, 195, 124, 140, 143, 206, 4,
                    144, 23, 37, 235, 10, 196,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.81".to_string(),
                pk: vec![
                    160, 237, 235, 31, 222, 216, 243, 2, 76, 157, 4, 144, 248, 184, 247, 78, 73, 203, 76, 189, 1, 82,
                    144, 11, 127, 110, 105, 207, 38, 129, 47, 220, 81, 62, 172, 79, 243, 151, 178, 66, 118, 103, 163,
                    171, 33, 199, 65, 34,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.102".to_string(),
                pk: vec![
                    166, 198, 0, 137, 253, 70, 181, 210, 250, 148, 76, 70, 185, 43, 96, 138, 159, 198, 62, 233, 112,
                    216, 128, 155, 3, 173, 115, 173, 250, 86, 18, 171, 44, 222, 78, 84, 210, 53, 139, 26, 140, 244,
                    233, 100, 186, 67, 232, 150,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.114".to_string(),
                pk: vec![
                    164, 12, 199, 133, 164, 137, 105, 149, 202, 31, 86, 140, 237, 86, 7, 197, 119, 5, 118, 114, 181,
                    66, 14, 54, 125, 196, 220, 246, 255, 162, 236, 66, 102, 126, 186, 88, 44, 176, 67, 254, 231, 204,
                    30, 233, 107, 65, 250, 149,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "46.17.103.22".to_string(),
                pk: vec![
                    152, 183, 179, 113, 223, 105, 38, 163, 165, 103, 6, 61, 52, 34, 100, 194, 159, 20, 51, 61, 225, 81,
                    201, 251, 234, 158, 84, 103, 67, 11, 151, 20, 67, 103, 52, 223, 38, 235, 41, 235, 49, 236, 113, 74,
                    76, 4, 111, 42,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.106".to_string(),
                pk: vec![
                    166, 226, 150, 226, 209, 58, 241, 66, 205, 214, 31, 213, 54, 205, 21, 138, 198, 206, 134, 195, 20,
                    194, 90, 31, 70, 184, 201, 112, 66, 7, 24, 193, 130, 255, 218, 153, 20, 28, 110, 199, 205, 21, 4,
                    19, 146, 225, 188, 98,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.100".to_string(),
                pk: vec![
                    145, 198, 196, 98, 156, 40, 107, 247, 6, 72, 239, 195, 72, 170, 86, 46, 113, 164, 225, 143, 234,
                    98, 239, 98, 91, 104, 54, 110, 40, 154, 140, 73, 180, 246, 105, 106, 77, 192, 153, 86, 40, 72, 113,
                    245, 91, 202, 83, 35,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.111".to_string(),
                pk: vec![
                    163, 9, 3, 218, 35, 39, 171, 66, 230, 57, 232, 100, 68, 190, 47, 8, 232, 117, 216, 228, 245, 134,
                    226, 55, 249, 73, 58, 161, 242, 247, 89, 40, 200, 206, 232, 135, 233, 203, 114, 212, 137, 34, 236,
                    179, 183, 120, 113, 186,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "37.27.238.30".to_string(),
                pk: vec![
                    166, 17, 122, 234, 47, 6, 152, 28, 74, 233, 20, 86, 46, 177, 78, 230, 138, 7, 244, 246, 32, 1, 234,
                    133, 34, 33, 166, 29, 17, 57, 81, 109, 176, 231, 71, 125, 198, 63, 3, 69, 149, 14, 176, 141, 196,
                    174, 253, 105,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 7),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "72.9.146.109".to_string(),
                pk: vec![
                    140, 87, 68, 82, 172, 81, 44, 100, 198, 56, 163, 161, 89, 254, 140, 250, 210, 93, 64, 174, 201,
                    163, 115, 112, 42, 10, 254, 26, 155, 34, 147, 21, 192, 74, 223, 38, 197, 12, 179, 241, 167, 174,
                    210, 127, 209, 29, 220, 161,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "156.67.62.246".to_string(),
                pk: vec![
                    137, 237, 30, 124, 177, 201, 85, 195, 64, 130, 201, 77, 249, 85, 10, 34, 34, 247, 223, 102, 209,
                    194, 170, 191, 144, 173, 106, 58, 88, 140, 168, 13, 243, 47, 193, 2, 109, 64, 44, 152, 240, 158,
                    24, 115, 93, 26, 209, 163,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "90.11.201.149".to_string(),
                pk: vec![
                    150, 236, 153, 58, 73, 122, 24, 38, 176, 142, 71, 131, 14, 160, 141, 64, 56, 126, 122, 114, 44,
                    174, 184, 59, 158, 83, 29, 17, 19, 95, 109, 105, 194, 126, 165, 77, 209, 223, 153, 247, 123, 127,
                    29, 62, 244, 162, 23, 136,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "139.60.162.57".to_string(),
                pk: vec![
                    152, 165, 48, 245, 194, 34, 23, 24, 202, 148, 70, 183, 118, 56, 35, 228, 51, 28, 110, 136, 10, 19,
                    239, 94, 165, 109, 37, 149, 224, 211, 3, 182, 112, 190, 51, 182, 198, 11, 203, 78, 45, 101, 102,
                    111, 144, 102, 78, 24,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "80.209.242.171".to_string(),
                pk: vec![
                    133, 5, 75, 57, 38, 172, 80, 8, 132, 198, 215, 183, 213, 195, 51, 21, 174, 55, 240, 163, 201, 52,
                    100, 68, 23, 153, 2, 111, 53, 215, 243, 183, 40, 179, 10, 94, 30, 36, 196, 93, 73, 146, 254, 4,
                    151, 62, 148, 174,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "67.222.138.150".to_string(),
                pk: vec![
                    134, 145, 35, 101, 204, 201, 60, 69, 96, 44, 49, 185, 238, 160, 215, 24, 211, 99, 51, 128, 110,
                    234, 186, 132, 187, 254, 158, 212, 7, 86, 185, 237, 44, 54, 223, 33, 167, 2, 61, 124, 67, 43, 141,
                    69, 131, 219, 157, 142,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "67.222.138.149".to_string(),
                pk: vec![
                    176, 32, 139, 243, 193, 110, 241, 22, 238, 99, 164, 242, 200, 166, 246, 49, 52, 204, 48, 18, 26,
                    39, 247, 230, 127, 201, 247, 237, 200, 51, 207, 168, 14, 165, 188, 193, 98, 24, 168, 54, 235, 65,
                    234, 127, 29, 248, 121, 190,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "185.130.227.22".to_string(),
                pk: vec![
                    134, 2, 90, 136, 252, 233, 10, 40, 253, 133, 208, 5, 222, 90, 83, 1, 65, 234, 34, 53, 60, 18, 18,
                    10, 135, 237, 133, 89, 188, 225, 223, 39, 132, 1, 169, 96, 227, 189, 160, 241, 127, 211, 79, 188,
                    11, 47, 111, 12,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "66.248.204.226".to_string(),
                pk: vec![
                    166, 145, 169, 227, 165, 208, 34, 57, 154, 222, 14, 123, 157, 195, 103, 121, 19, 187, 233, 168,
                    116, 178, 197, 101, 18, 241, 21, 222, 179, 184, 174, 103, 42, 243, 58, 28, 36, 36, 108, 173, 118,
                    24, 38, 19, 69, 157, 143, 197,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "152.114.194.195".to_string(),
                pk: vec![
                    175, 113, 7, 170, 56, 76, 181, 131, 12, 230, 224, 38, 138, 190, 174, 143, 161, 165, 156, 236, 217,
                    62, 228, 164, 143, 91, 168, 176, 89, 236, 32, 18, 202, 109, 25, 134, 57, 58, 28, 2, 14, 232, 34,
                    36, 144, 113, 93, 210,
                ],
            },
            SeedANR {
                version: Ver::new(1, 1, 8),
                port: 36969,
                ts: 1755802866,
                signature: vec![],
                ip4: "194.180.188.146".to_string(),
                pk: vec![
                    164, 85, 159, 90, 191, 148, 20, 192, 111, 157, 233, 127, 194, 157, 97, 198, 242, 70, 23, 195, 111,
                    100, 38, 244, 211, 74, 39, 112, 182, 186, 115, 253, 103, 198, 137, 108, 50, 92, 11, 192, 0, 53, 63,
                    215, 212, 129, 46, 175,
                ],
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
        let pop = bls12_381::sign(&sk, &pk, crate::consensus::DST_POP)
            .map(|sig| sig.to_vec())
            .unwrap_or_else(|_| vec![0u8; 96]);
        let seed_ips = SEED_NODES.iter().map(|s| s.parse()).collect::<Result<Vec<Ipv4Addr>, _>>().unwrap_or_default();

        Self {
            work_folder: ".config/rs_amadeusd".to_string(),
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

pub fn get_pk(sk: &[u8; 64]) -> [u8; 48] {
    bls12_381::get_public_key(sk).unwrap() // 64-byte sk is always be valid
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
