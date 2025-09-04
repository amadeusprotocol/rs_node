/// The only file where reading environment variables is allowed
/// Basically, the config for the whole the core library
use crate::node::anr::Anr;
use crate::utils::bls12_381;
pub use crate::utils::bls12_381::generate_sk as gen_sk;
use crate::utils::ip_resolver::resolve_public_ipv4;
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
pub const CLEANUP_SECS: u64 = 8; // how often node does the cleanup
pub const ANR_CHECK_SECS: u64 = 1; // how often node checks ANR status

pub const VERSION: [u8; 3] = parse_version();

const fn parse_version() -> [u8; 3] {
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
    out
}

pub const SEED_NODES: &[&str] = &[
    "104.218.45.23",
    "136.243.51.155",
    "139.60.162.57",
    "152.114.194.143",
    "152.114.194.161",
    "152.114.194.195",
    "156.67.62.246",
    "176.9.24.34",
    "178.237.58.137",
    "178.237.58.139",
    "178.237.58.203",
    "178.237.58.217",
    "178.237.58.218",
    "185.105.111.184",
    "185.130.227.22",
    "185.148.38.16",
    "188.213.129.120",
    "194.147.214.237",
    "194.147.214.238",
    "194.164.217.150",
    "194.180.188.146",
    "194.180.207.108",
    "194.180.207.39",
    "195.26.231.137",
    "195.26.231.9",
    "205.172.57.173",
    "205.172.59.6",
    "212.108.83.119",
    "212.108.83.192",
    "212.108.83.245",
    "212.237.219.142",
    "212.237.219.67",
    "217.123.171.82",
    "31.207.47.135",
    "35.91.34.26",
    "35.94.234.66",
    "37.228.93.218",
    "37.27.238.10",
    "37.27.238.30",
    "38.83.202.35",
    "38.83.202.36",
    "38.83.202.37",
    "38.83.202.38",
    "38.83.202.39",
    "38.83.202.40",
    "38.83.202.41",
    "38.83.202.42",
    "38.83.202.43",
    "38.83.202.44",
    "38.83.202.45",
    "38.83.202.46",
    "38.83.202.47",
    "38.83.202.48",
    "38.83.202.49",
    "38.83.202.53",
    "38.83.202.62",
    "38.83.202.63",
    "38.83.202.64",
    "38.83.202.66",
    "46.17.103.22",
    "46.17.96.23",
    "46.4.13.251",
    "5.39.221.243",
    "62.109.16.125",
    "62.169.17.132",
    "66.151.40.64",
    "66.248.204.226",
    "67.222.138.149",
    "67.222.138.150",
    "67.222.157.66",
    "67.222.157.68",
    "72.9.144.110",
    "72.9.146.100",
    "72.9.146.101",
    "72.9.146.102",
    "72.9.146.103",
    "72.9.146.104",
    "72.9.146.105",
    "72.9.146.106",
    "72.9.146.107",
    "72.9.146.108",
    "72.9.146.109",
    "72.9.146.110",
    "72.9.146.111",
    "72.9.146.112",
    "72.9.146.113",
    "72.9.146.114",
    "72.9.146.115",
    "72.9.146.116",
    "72.9.146.70",
    "72.9.146.71",
    "72.9.146.72",
    "72.9.146.73",
    "72.9.146.75",
    "72.9.146.76",
    "72.9.146.77",
];

// seed anr from elixir config/config.exs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedANR {
    pub ip4: String,
    pub port: u16,
    pub version: String,
    pub signature: Vec<u8>,
    pub ts: u32,
    pub pk: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
    pub version_3b: [u8; 3],

    // network configuration
    pub offline: bool,
    pub http_ipv4: Ipv4Addr,
    pub http_port: u16,
    pub udp_ipv4: Ipv4Addr,
    pub udp_port: u16,
    pub public_ipv4: Option<String>,

    // node discovery
    pub seed_nodes: Vec<String>,
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

    pub fn get_ver(&self) -> String {
        self.version_3b.iter().map(|b| b.to_string()).collect::<Vec<String>>().join(".")
    }

    pub fn get_public_ipv4(&self) -> Ipv4Addr {
        self.public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1))
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

        let version_3b = VERSION;

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
        let seed_nodes = SEED_NODES.iter().map(|s| s.to_string()).collect();
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

        let ver = version_3b.iter().map(|b| b.to_string()).collect::<Vec<String>>().join(".");
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
                ver.clone(),
                anr_name.clone(),
                anr_desc.clone(),
            )
            .ok()
        });

        let seed_anrs = vec![SeedANR {
            version: "1.1.6".to_string(),
            port: 36969,
            ts: 1755802866,
            signature: vec![],
            ip4: "72.9.144.110".to_string(),
            pk: vec![
                169, 232, 30, 216, 200, 234, 174, 189, 141, 213, 58, 136, 157, 140, 90, 134, 18, 171, 115, 48, 39, 90,
                93, 57, 4, 62, 149, 32, 14, 124, 27, 102, 240, 220, 0, 197, 48, 126, 134, 122, 85, 169, 173, 158, 122,
                228, 185, 240,
            ],
        }];

        Ok(Self {
            work_folder,
            version_3b,
            offline,
            http_ipv4,
            http_port,
            udp_ipv4,
            udp_port,
            public_ipv4,
            seed_nodes,
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

    pub fn from_sk(sk: [u8; 64]) -> Self {
        let pk = get_pk(&sk);
        let pk_b58 = bs58::encode(pk).into_string();
        let pop = bls12_381::sign(&sk, &pk, crate::consensus::DST_POP)
            .map(|sig| sig.to_vec())
            .unwrap_or_else(|_| vec![0u8; 96]);

        Self {
            work_folder: ".config/rs_amadeusd".to_string(),
            version_3b: VERSION,
            offline: false,
            http_ipv4: Ipv4Addr::new(0, 0, 0, 0),
            http_port: 80,
            udp_ipv4: Ipv4Addr::new(0, 0, 0, 0),
            udp_port: 36969,
            public_ipv4: None,
            seed_nodes: SEED_NODES.iter().map(|s| s.to_string()).collect(),
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
