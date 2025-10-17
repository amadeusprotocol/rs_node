//! Coin Symbol reservation checks

use std::collections::HashMap;
use std::sync::LazyLock;

/// Represents reservation status for a symbol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservedOwner {
    /// Reserved for a specific owner pubkey
    Owner([u8; 48]),
    /// Reserved but no specific owner (blocks everyone, matches Elixir's `true`)
    Blocked,
}

static RESERVED_LIST: LazyLock<HashMap<&'static str, ReservedOwner>> = LazyLock::new(|| {
    let symbols = [
        "AMA", "BTC", "ETH", "USDT", "XRP", "BNB", "SOL", "USDC", "DOGE", "ADA", "TRX", "STETH",
        "WBTC", "SUI", "LINK", "AVAX", "XLM", "LEO", "USDS", "SHIB", "TON", "HBAR", "WSTETH",
        "BCH", "HYPE", "LTC", "DOT", "WETH", "BSC-USD", "BGB", "XMR", "USDE", "PI", "WBT", "CBBTC",
        "WEETH", "PEPE", "DAI", "APT", "SUSDS", "OKB", "TAO", "UNI", "NEAR", "BUIDL", "ONDO",
        "AAVE", "GT", "ETC", "ICP", "KAS", "MNT", "CRO", "TKX", "RENDER", "TRUMP", "VET", "USD1",
        "SUSDE", "POL", "LBTC", "ATOM", "FTN", "FET", "ALGO", "FIL", "S", "ENA", "JLP", "ARB",
        "TIA", "FDUSD", "SOLVBTC", "KCS", "BONK", "WLD", "MKR", "NEXO", "QNT", "JUP", "FLR", "STX",
        "BNSOL", "XDC", "OP", "EOS", "VIRTUAL", "FARTCOIN", "SEI", "RSETH", "USDT0", "IMX", "IP",
        "INJ", "PYUSD", "CRV", "GRT", "WBNB", "RETH", "DEXE", "XAUT", "JASMY", "RAY", "PAXG",
        "IOTA", "MSOL", "FLOKI", "CLBTC", "JUPSOL", "BSV", "LDO", "XSOLVBTC", "BTT", "THETA",
        "METH", "GALA", "SAND", "HNT", "CORE", "KAIA", "WAL", "LAYER", "USD0", "PENGU", "ENS",
        "CAKE", "USDX", "FLOW", "USDY", "EZETH", "XTZ", "ZEC", "WIF", "BRETT", "XCN", "MANA",
        "PENDLE", "USDC.E", "JTO", "AERO", "PYTH", "TEL", "UBTC", "RSR", "TUSD", "OSETH", "BTC.B",
        "SPX", "AR", "BDX", "AIOZ", "RUNE", "DYDX", "OUSG", "PUMPBTC", "KAVA", "EGLD", "TBTC",
        "DEEP", "XEC", "MOVE", "NFT", "NEO", "GRASS", "USYC", "STRK", "USDB", "OM", "APE",
        "SUPEROETH", "CMETH", "AXS", "BEAM", "CHZ", "MATIC", "CFX", "BERA", "W", "OHM", "POPCAT",
        "COMP", "EETH", "AKT", "JST", "MWC", "MORPHO", "PLUME", "RON", "SAROS", "SUN", "AXL",
        "CGETH.HASHKEY", "USDD", "AMP", "TWT", "TURBO", "BUSD", "LUNC", "FRAX", "RLUSD", "SUPER",
        "CTC", "CHEEMS", "KET", "WHYPE", "BERASTONE", "GNO", "VENOM", "WAVAX", "MINA", "AI16Z",
        "EBTC", "ZRO", "1INCH", "DASH", "USR", "DOG", "QGOLD", "ETHX", "HONEY", "MX", "SFP",
        "SAFE", "GLM", "SYRUPUSDC", "TFUEL", "ATH", "SNEK", "MEW", "CVX", "CWBTC", "CBETH", "KSM",
        "IBERA", "USDG", "SWETH", "GHO", "ZIL", "ABTC", "BTSE", "EIGEN", "NOT", "BLUR", "SNX",
        "EURC", "LSETH", "MOCA", "QTUM", "USDF", "VRSC", "FRXETH", "VTHO", "CKB", "ZRX", "MOG",
        "ARKM", "BAT", "KDA", "SAVAX", "BBSOL", "ZETA", "ASTR", "BABYDOGE", "GAS", "DCR", "DSOL",
        "USDA", "TRIP", "BABY", "TRAC", "STG", "CELO", "BORG", "ROSE", "ZK", "LPT", "KAITO",
        "STHYPE", "ANKR", "SYRUP", "CSPR", "CHEX", "AGENTFUN", "SC", "YFI", "ONE", "PRIME",
        "EUTBL", "GAMA", "UXLINK", "ELF", "DEUSD", "XYO", "DRIFT", "T", "GIGA", "ZANO", "HOT",
        "AIC", "RVN", "IOTX", "LVLUSD", "PNUT", "TETH", "HMSTR", "$RCGE", "POLYX", "CET", "XEM",
        "ETHW", "TOSHI", "SFRXETH", "XCH", "VANA", "SOS", "ORCA", "KOGE", "DGB", "FLUID", "QUBIC",
        "GOMINING", "CRVUSD", "MPLX", "WEMIX", "ORDI", "OSMO", "GMT", "KAU", "USDO", "EUL", "DLC",
        "TRIBE", "PUNDIX", "ALCH", "AIXBT", "EURS", "ZBCN", "SQD", "ME", "RLB", "CUSDO", "WBETH",
        "SWFTC", "MAG7.SSI", "WOO", "KULA", "DAG", "ILV", "ENJ", "GMX", "MELANIA", "BIGTIME",
        "ZEN", "COTI", "CONSCIOUS", "WMTX", "KUB", "ONT", "LCX", "GOHOME", "AMAPT", "CETUS",
        "STEAKUSDC", "ZKJ", "ACH", "STRAX", "NPC", "ETHFI", "KAG", "MEOW", "FAI", "SXP", "ASBNB",
        "SKL", "PWR", "STPT", "STS", "USDZ", "BAND", "XNO", "SUSHI", "SDEUSD", "PAAL", "LRC",
        "OPT", "B3", "ZIG", "COW", "LUNA", "HIVE", "ETH+", "OZO", "MYTH", "IO", "APFC", "NXM",
        "NKYC", "BDCA", "ARDR", "VVV", "GAL", "WAVES", "MASK", "DAKU", "BICO", "FLUX", "BIO",
        "VCNT", "VVS", "BORA", "INIT", "G", "REUSD", "ICX", "PROM", "ANIME", "CPOOL", "WFRAGSOL",
        "ABT", "AGI", "FBTC", "NTGL", "RED", "SIGN", "ZEUS", "QUSDT", "STBTC", "USDL", "USUAL",
        "XPR", "BOME", "PEAQ", "UMA", "KMNO", "XVS", "SGB", "SBTC", "SONIC", "METIS", "WELL",
        "OSAK", "ORBS", "XMW", "SUPRA", "W3S", "REQ", "FRXUSD", "OKT", "LSK", "AUDIO", "NEIRO",
        "ECOIN", "SSOL", "GCB", "ALT", "VELO", "AGIX", "ACT", "AEVO", "COREUM", "BLAST", "MVL",
        "POWR", "CGPT", "IQ", "ACX", "MANTA", "SPELL", "BMX", "IOST", "VEE", "SNT", "PUNDIAI",
        "ALEO", "ZRC", "XRD", "HEART", "AERGO", "CARV", "RPL", "UXP", "DYM", "SUSDA", "MEME",
        "ID", "TEMPLE", "API3", "CVC", "YGG", "AGLD", "SATS", "ONG", "USTBL", "WAXP", "ZENT",
        "DKA", "OETH", "GFI", "RLC", "SOLO", "ARK", "OMNI", "BONE", "ACRED", "CETH", "XVG", "H2O",
        "PHA", "REUSDC", "MLK", "NMD", "CSUSDL", "LON", "GLMR", "TNQ", "SOLVBTC.JUP", "ANDY",
        "FIDA", "TRB", "POND", "ROAM", "DOGS", "RSWETH", "RUSD", "DENT", "UNP", "AUCTION", "MED",
        "GEOD", "CFG", "STEEM", "PCI", "CTF", "JOE", "GOAT", "CHR", "PROMPT", "ELON", "USDP",
        "NOS", "PEOPLE", "COOKIE", "MIU", "AVA", "HOUSE", "AVAIL", "TAIKO", "NIL", "SAGA", "SLND",
        "NMR", "BAL", "0X0", "MTL", "IAG", "WCT", "PTGC", "SOLVBTC.CORE", "SLP", "DEGEN", "SCRT",
        "USTC", "EZSOL", "NILA", "SAAS", "PURR", "BUCK", "ANON", "BANANA", "LQTY", "AITECH",
        "SFRAX", "GAME", "DOLA", "GRIFFAIN", "DESO", "ACS", "DIA", "XAI", "BGSC", "BITCOIN", "B2M",
        "ERG", "OCEAN", "RLP", "TST", "OAS", "APU", "SHFL", "KNC", "SIREN", "ORAI", "PUFF", "AIAT",
        "FMC", "MOVR", "IGT", "OMI", "USUALX", "VANRY", "PONKE", "UDS", "ARC", "WOLF", "ISLM",
        "CTK", "MWETH", "SCR", "DEVVE", "MIM", "SOLV", "CX", "PZETH", "C98", "MAGIC", "SYN", "PIN",
        "CTSI", "TRUAPT", "BTU", "BERAETH", "QKC", "CELR", "WPOL", "GUSD", "QI", "HDX", "SLVLUSD",
        "ALI", "BNT", "AURORA", "WIN", "DF", "MNSRY", "AVUSD", "AO", "FUEL", "HPO", "REI", "HUNT",
        "CBK", "PEPECOIN", "ELG", "CCD", "FEUSD", "SKI", "ETHDYDX", "RARE", "CORGIAI", "WILD",
        "NMT", "HSK", "FUN", "JNFTC", "AXGT", "BB", "AGETH", "USD+", "USDM", "FIUSD", "ANT",
        "MEMEFI", "PARTI", "TRU", "HT", "TNSR", "SHELL", "EURCV", "SAVUSD", "SUNDOG", "CUDOS",
        "METFI", "WFCA", "TAI", "DBR", "CHILLGUY", "BANANAS31", "APEX", "SN", "WEETH", "MERL",
        "TOKEN", "CYBER", "KTA", "ZEREBRO", "AVL", "FWOG", "KEEP", "USD3", "DODO", "OLAS", "METAL",
        "ZEDXION", "SHX", "LADYS", "MBL", "WZRD", "LUSD", "RAIL", "RIF", "MOBILE", "SSV", "GNS",
        "SDEX", "STONKS", "REKT", "RSS3", "SILO", "CAT", "BAN", "BFC", "PRO", "ICE", "INF", "KUJI",
        "AUX", "STRIKE", "FORT", "AUKI", "QANX", "SFUND", "STORJ", "ANVL", "WSTUSR", "STMX", "OXT",
        "META", "EWT", "COQ", "EDGE", "AZERO", "MCDULL", "GORK", "EVER", "M87", "NYM", "OGN",
        "ALICE", "DEGO", "WXRP", "EKUBO", "MOODENG", "MBX", "SPA", "SKYAI", "STO", "RAD", "SYS",
        "NCT", "VINE", "DUSK", "BMT", "AMPL", "ROOT", "A8", "PRCL", "TT", "GODS", "LISUSD", "SCBTC",
        "CXO", "OBT", "GRND", "L3", "SOSO", "ACA", "UQC", "BINK", "NTRN", "HFUN", "ALPH", "XT",
        "GPS", "BC", "MNDE", "THAPT", "NEURAL", "TLOS", "HIFI", "MILK", "GEAR", "KYSOL", "DAO",
        "GNUS", "JELLYJELLY", "CUSD", "ALEX", "BOBA", "SWEAT", "CUSDC", "HBD", "SB", "SERAPH",
        "IXS", "QRL", "RACA", "EGGS", "FIS", "REG", "BIM", "MAV", "EDU", "RSC", "LMWR", "ASM",
        "DEP", "SLERF", "MIN", "REZ", "J", "ALPACA", "ZORA", "AINTI", "SURE", "TRUMATIC", "BAKE",
        "ACE", "HFT", "ERN", "TIBBIR", "XTER", "GPU", "XTUSD", "DRGN", "FORTH", "PLT", "SCRVUSD",
        "NFP", "EL", "VADER", "BROCCOLI", "AQT", "MATICX", "ORA", "DEFI", "DOGINME", "SUSD", "FCT",
        "ATA", "GRS", "BXN", "ANYONE", "SAUCE", "AIDOGE", "HOOK", "TORN", "NS", "TKP", "XPLA",
        "LAT", "MIGGLES", "DXI", "CLV", "PNG", "DG", "GUN", "MOC", "FROK", "HEGIC", "SPEC", "EFI",
        "TLM", "WIBE", "VRO", "LOKA", "SRX", "USDT.E", "A47", "TREE", "CORN", "HMT", "MUBARAK",
        "REX", "EPIC", "XION", "CLANKER", "MRB", "QUAI", "TROLL", "SD", "MAPO", "ASUSDF", "NEON",
        "ZCX", "LISTA", "GFAL", "BOLD", "ALPHA", "SEND", "SWARMS", "BMEX", "RDNT", "LOFI", "EURT",
        "PHB", "UNIETH", "CXT", "BURN", "KEYCAT", "HYPER", "BLUE", "CULT", "TRYB", "D", "HAEDAL",
        "OMG", "LHYPE", "SFRXUSD", "WNXM", "WHITE", "OGY", "LBT", "PEAS", "POKT", "CRTS", "B2",
        "MIMATIC", "MBOX", "SSUI", "$FARTBOY", "ETN", "OFT", "PIXEL", "NKN", "STRD", "GXC",
        "KERNEL", "SERV", "ELA", "SPECTRE", "MYRIA", "VICE", "EURE", "IBGT", "BEL", "VOW", "GOTS",
        "SX", "AHT", "CAM", "NAKA", "VITA", "CAW", "WEN", "BOUNTY", "ORDER", "OL", "HASHAI", "QUIL",
    ];
    symbols.into_iter().map(|s| (s, ReservedOwner::Blocked)).collect()
});

/// Returns true if the symbol is available for use by the caller
pub fn is_free(symbol: &str, caller: &[u8; 48]) -> bool {
    let upcase = symbol.to_uppercase();
    let in_reserve = reserved_list_lookup(&upcase);

    // cond logic from Elixir:
    // in_reserve == caller -> true  (only matches if Owner(pk) == caller)
    // String.starts_with?(upcase_symbol, "AMA") -> false
    // !in_reserve -> true
    // true -> false

    match in_reserve {
        Some(ReservedOwner::Owner(pk)) if &pk == caller => true,
        Some(_) => false, // blocked or owner mismatch
        None => !upcase.starts_with("AMA"), // free unless starts with "AMA"
    }
}

fn reserved_list_lookup(symbol: &str) -> Option<ReservedOwner> {
    RESERVED_LIST.get(symbol).cloned()
}
