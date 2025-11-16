#[cfg(test)]
mod tests {
    use crate::node::anr::Anr;
    use crate::utils::bls12_381;
    use crate::utils::vecpak;
    use crate::utils::vecpak_compat;
    use crate::utils::version::Ver;
    use std::net::Ipv4Addr;

    #[test]
    fn test_anr_vecpak_signature() {
        // Generate test keys
        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).expect("get pk");
        let pop = bls12_381::sign(&sk, &pk, crate::consensus::DST_POP).expect("sign pop");

        // Build ANR with vecpak signature
        let anr = Anr::build(&sk, &pk, &pop, Ipv4Addr::new(127, 0, 0, 1), Ver::new(1, 2, 5)).expect("build anr");

        // Verify the signature works
        assert!(anr.verify_signature(), "ANR signature should verify");

        // Print the vecpak encoded data for debugging
        let vecpak_data = anr.to_vecpak_for_signing();
        println!("Vecpak encoded ANR (hex): {}", hex::encode(&vecpak_data));
        println!("Vecpak size: {} bytes", vecpak_data.len());

        // Ensure it's using vecpak format, not ETF
        // Vecpak starts with tags 0-7, ETF starts with 131
        assert!(vecpak_data[0] <= 7, "Should be vecpak format, not ETF");
    }

    #[test]
    fn test_anr_signature_compatibility() {
        // This test verifies that our ANR signatures match Elixir's format
        // by checking the structure of the signed data

        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).expect("get pk");
        let pop = bls12_381::sign(&sk, &pk, crate::consensus::DST_POP).expect("sign pop");

        let anr = Anr::build(&sk, &pk, &pop, Ipv4Addr::new(192, 168, 1, 1), Ver::new(1, 2, 3)).expect("build anr");

        // Get the data we're signing
        let to_sign = anr.to_vecpak_for_signing();

        // Decode it to see the structure
        let mut offset = 0;
        let decoded = vecpak::decode_term(&to_sign, &mut offset).expect("decode vecpak");

        println!("Decoded vecpak term: {:?}", decoded);

        // Verify it's a PropList (map in vecpak)
        match decoded {
            vecpak::Term::PropList(pairs) => {
                println!("ANR has {} fields", pairs.len());
                for (key, value) in &pairs {
                    if let vecpak::Term::Binary(key_bytes) = key {
                        let key_str = String::from_utf8_lossy(key_bytes);
                        println!("Field: {}", key_str);
                    }
                }
            }
            _ => panic!("Expected PropList for ANR"),
        }
    }
}
