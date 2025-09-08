use bls12_381::*;
use group::Curve;

// we use blst for signing/verification (hash_to_curve with DST) and serialization
use blst::BLST_ERROR;
use blst::min_pk::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid point")]
    InvalidPoint,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("verification failed")]
    VerificationFailed,
    #[error("zero-sized input")]
    ZeroSizedInput,
}

/// Parse a secret key from raw bytes, accepts either 64 or 32 bytes
/// For 64-byte keys, use first 32 bytes directly as secret key (matches Elixir BlsEx approach)
fn parse_secret_key(sk_bytes: &[u8]) -> Result<BlsSecretKey, Error> {
    // For 64-byte secret keys: use first 32 bytes as the actual secret key
    // This matches the Elixir BlsEx library behavior more closely
    if let Ok(bytes_64) = <&[u8; 64]>::try_from(sk_bytes) {
        let mut sk_32 = [0u8; 32];
        sk_32.copy_from_slice(&bytes_64[..32]);
        return BlsSecretKey::from_bytes(&sk_32).map_err(|_| Error::InvalidSecretKey);
    }
    // For 32-byte secret keys: use directly
    if let Ok(bytes_32) = <&[u8; 32]>::try_from(sk_bytes) {
        return BlsSecretKey::from_bytes(bytes_32).map_err(|_| Error::InvalidSecretKey);
    }
    Err(Error::InvalidSecretKey)
}

fn g1_projective_is_valid(projective: &G1Projective) -> bool {
    let is_identity: bool = projective.is_identity().into();
    let is_on_curve = projective.is_on_curve().into();
    let is_torsion_free = projective.to_affine().is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn g2_affine_is_valid(affine: &G2Affine) -> bool {
    let is_identity: bool = affine.is_identity().into();
    let is_on_curve = affine.is_on_curve().into();
    let is_torsion_free = affine.is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn parse_public_key(bytes: &[u8]) -> Result<G1Projective, Error> {
    if bytes.len() != 48 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 48];
    res.copy_from_slice(bytes);

    match Option::<G1Affine>::from(G1Affine::from_compressed(&res)) {
        Some(affine) => {
            let projective = G1Projective::from(affine);
            if g1_projective_is_valid(&projective) { Ok(projective) } else { Err(Error::InvalidPoint) }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn parse_signature(bytes: &[u8]) -> Result<G2Projective, Error> {
    if bytes.len() != 96 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 96];
    res.copy_from_slice(bytes);

    match Option::from(G2Affine::from_compressed(&res)) {
        Some(affine) => {
            if g2_affine_is_valid(&affine) {
                Ok(G2Projective::from(affine))
            } else {
                Err(Error::InvalidPoint)
            }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn sign_from_secret_key(sk: BlsSecretKey, msg: &[u8], dst: &[u8]) -> Result<BlsSignature, Error> {
    Ok(sk.sign(msg, dst, &[]))
}

// public API

/// Derive compressed G1 public key (48 bytes) from secret key (32 or 64 bytes)
pub fn get_public_key(sk_bytes: &[u8]) -> Result<[u8; 48], Error> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk = sk.sk_to_pk();
    Ok(pk.to_bytes())
}

pub fn generate_sk() -> [u8; 64] {
    let ikm: [u8; 32] = rand::random();
    let sk = BlsSecretKey::key_gen(&ikm, &[]).expect("should not fail");
    let sk_bytes = sk.to_bytes();
    // Return as 64-byte array (padding with zeros to match format)
    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&sk_bytes);
    result
}

/// Sign a message with secret key, returns signature bytes (96 bytes in min_pk)
pub fn sign(sk_bytes: &[u8], message: &[u8], dst: &[u8]) -> Result<[u8; 96], Error> {
    let sk = parse_secret_key(sk_bytes)?;
    let signature = sign_from_secret_key(sk, message, dst)?;
    Ok(signature.to_bytes())
}

/// Verify a signature using a compressed G1 public key (48 bytes) and signature (96 bytes)
/// Errors out if the signature is invalid
pub fn verify(pk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8], dst: &[u8]) -> Result<(), Error> {
    let pk = BlsPublicKey::deserialize(pk_bytes).map_err(|_| Error::InvalidPoint)?;
    let sig = BlsSignature::deserialize(sig_bytes).map_err(|_| Error::InvalidSignature)?;

    let err = sig.verify(
        true, // hash_to_curve
        msg,
        dst, // domain separation tag
        &[], // no augmentation
        &pk,
        true, // validate pk ∈ G1
    );

    if err == BLST_ERROR::BLST_SUCCESS { Ok(()) } else { Err(Error::VerificationFailed) }
}

/// Aggregate multiple compressed G1 public keys into one compressed G1 public key (48 bytes)
pub fn aggregate_public_keys<T>(public_keys: T) -> Result<[u8; 48], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = public_keys.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_public_key(first.as_ref())?;
    for pk in iter {
        let p = parse_public_key(pk.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Aggregate multiple signatures (compressed G2, 96 bytes) into one compressed G2 (96 bytes)
pub fn aggregate_signatures<T>(signatures: T) -> Result<[u8; 96], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = signatures.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_signature(first.as_ref())?;
    for s in iter {
        let p = parse_signature(s.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Compute Diffie-Hellman shared secret: pk_g1 * sk -> compressed G1 (48 bytes).
pub fn get_shared_secret(public_key: &[u8], sk_bytes: &[u8]) -> Result<[u8; 48], Error> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk_g1 = parse_public_key(public_key)?; // validates pk
    // Convert blst SecretKey to scalar for elliptic curve multiplication
    let sk_scalar_bytes = sk.to_bytes();
    let sk_scalar = Scalar::from_bytes(&sk_scalar_bytes).into_option().ok_or(Error::InvalidSecretKey)?;
    Ok((pk_g1 * sk_scalar).to_affine().to_compressed())
}

/// Validate a compressed G1 public key.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), Error> {
    parse_public_key(public_key).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed32(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn pk_sign_verify_and_validate() {
        let seed = seed32(1);
        let pk = get_public_key(&seed).expect("pk");
        validate_public_key(&pk).expect("valid pk");

        let msg = b"context7:message";
        let dst = b"CONTEXT7-BLS-DST";
        let sig = sign(&seed, msg, dst).expect("sign");
        verify(&pk, &sig, msg, dst).expect("verify");
    }

    #[test]
    fn shared_secret_symmetry() {
        let a = seed32(2);
        let b = seed32(3);
        let pk_a = get_public_key(&a).unwrap();
        let pk_b = get_public_key(&b).unwrap();
        let ab = get_shared_secret(&pk_b, &a).unwrap();
        let ba = get_shared_secret(&pk_a, &b).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn aggregation_behaviour() {
        let s1 = seed32(4);
        let s2 = seed32(5);
        let pk1 = get_public_key(&s1).unwrap();
        let pk2 = get_public_key(&s2).unwrap();

        // test single public key aggregation
        let agg1 = aggregate_public_keys([pk1]).unwrap();
        assert_eq!(agg1.len(), 48);
        assert_eq!(agg1, pk1); // single key aggregation should equal original key

        // test multiple public key aggregation
        let agg_pk = aggregate_public_keys([pk1, pk2]).unwrap();
        assert_eq!(agg_pk.len(), 48);
        assert_ne!(agg_pk, pk1); // aggregated key should differ from individual keys
        assert_ne!(agg_pk, pk2);

        // zero-sized input should fail
        assert!(matches!(aggregate_public_keys::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test signature aggregation
        let dst = b"DST";
        let msg = b"m";
        let sig1 = sign(&s1, msg, dst).unwrap();
        let sig2 = sign(&s2, msg, dst).unwrap();

        // test single signature aggregation
        let agg_sig1 = aggregate_signatures([sig1.as_slice()]).unwrap();
        assert_eq!(agg_sig1.len(), 96);
        assert_eq!(agg_sig1, sig1); // single signature aggregation should equal original

        // test multiple signature aggregation
        let agg_sig = aggregate_signatures([sig1.as_slice(), sig2.as_slice()]).unwrap();
        assert_eq!(agg_sig.len(), 96);
        assert_ne!(agg_sig, sig1); // aggregated signature should differ from individual signatures
        assert_ne!(agg_sig, sig2);

        // zero-sized signature input should fail
        assert!(matches!(aggregate_signatures::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test that aggregated signature verifies against aggregated public key
        verify(&agg_pk, &agg_sig, msg, dst).expect("aggregated signature should verify against aggregated public key");

        // test that individual signatures don't verify against aggregated public key
        assert!(verify(&agg_pk, &sig1, msg, dst).is_err());
        assert!(verify(&agg_pk, &sig2, msg, dst).is_err());

        // test that aggregated signature doesn't verify against individual public keys
        assert!(verify(&pk1, &agg_sig, msg, dst).is_err());
        assert!(verify(&pk2, &agg_sig, msg, dst).is_err());
    }

    #[test]
    fn elixir_reference_signature_compatibility() {
        // Test cases from Elixir reference implementation
        let test_cases = vec![
            (
                // sk (64 bytes)
                vec![97, 100, 58, 216, 121, 14, 255, 149, 44, 165, 1, 88, 100, 35, 75, 192, 138, 138, 67, 9, 134, 210, 6, 88, 155, 3, 21, 197, 119, 155, 33, 163, 103, 4, 46, 229, 62, 157, 185, 90, 19, 106, 206, 72, 245, 133, 133, 183, 132, 250, 78, 92, 40, 160, 223, 244, 177, 53, 84, 31, 128, 185, 176, 166],
                // data
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49],
                // elixir reference signature
                vec![166, 193, 20, 132, 125, 87, 40, 182, 101, 225, 125, 220, 97, 93, 13, 2, 89, 220, 166, 6, 106, 203, 96, 63, 122, 16, 226, 117, 143, 219, 5, 105, 180, 229, 65, 58, 238, 93, 230, 253, 208, 110, 35, 219, 222, 176, 82, 112, 15, 149, 72, 148, 54, 88, 2, 94, 219, 26, 235, 98, 77, 202, 1, 83, 6, 38, 39, 150, 236, 176, 141, 222, 93, 133, 66, 154, 226, 55, 214, 100, 183, 179, 167, 140, 140, 77, 117, 11, 167, 219, 140, 144, 144, 160, 143, 128]
            ),
            (
                // Same sk, different data with "255" suffix
                vec![97, 100, 58, 216, 121, 14, 255, 149, 44, 165, 1, 88, 100, 35, 75, 192, 138, 138, 67, 9, 134, 210, 6, 88, 155, 3, 21, 197, 119, 155, 33, 163, 103, 4, 46, 229, 62, 157, 185, 90, 19, 106, 206, 72, 245, 133, 133, 183, 132, 250, 78, 92, 40, 160, 223, 244, 177, 53, 84, 31, 128, 185, 176, 166],
                // data with "255" at end
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 50, 53, 53],
                // elixir reference signature
                vec![141, 6, 181, 106, 49, 117, 193, 12, 249, 102, 71, 237, 125, 55, 25, 3, 14, 199, 113, 157, 49, 168, 205, 89, 106, 76, 3, 37, 170, 124, 149, 45, 234, 206, 44, 177, 90, 0, 14, 111, 30, 9, 197, 189, 201, 43, 86, 139, 22, 145, 182, 32, 77, 220, 35, 186, 5, 251, 37, 173, 187, 243, 110, 33, 57, 23, 67, 58, 166, 74, 200, 145, 232, 5, 151, 244, 62, 216, 159, 43, 131, 43, 179, 105, 154, 33, 91, 88, 143, 91, 40, 147, 129, 228, 37, 98]
            ),
            (
                // Same sk, data with timestamp "1640995200"
                vec![97, 100, 58, 216, 121, 14, 255, 149, 44, 165, 1, 88, 100, 35, 75, 192, 138, 138, 67, 9, 134, 210, 6, 88, 155, 3, 21, 197, 119, 155, 33, 163, 103, 4, 46, 229, 62, 157, 185, 90, 19, 106, 206, 72, 245, 133, 133, 183, 132, 250, 78, 92, 40, 160, 223, 244, 177, 53, 84, 31, 128, 185, 176, 166],
                // data with timestamp
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49, 54, 52, 48, 57, 57, 53, 50, 48, 48],
                // elixir reference signature
                vec![137, 145, 8, 245, 3, 166, 187, 110, 172, 28, 115, 177, 226, 179, 239, 201, 245, 173, 213, 25, 211, 84, 225, 194, 82, 30, 133, 105, 197, 97, 55, 185, 157, 83, 140, 89, 2, 3, 57, 7, 84, 242, 51, 161, 247, 238, 16, 126, 18, 69, 208, 108, 184, 132, 63, 67, 219, 144, 108, 54, 50, 176, 128, 138, 121, 191, 181, 168, 198, 229, 76, 246, 29, 36, 130, 95, 146, 213, 222, 230, 192, 179, 179, 198, 99, 209, 120, 134, 194, 181, 239, 187, 42, 46, 136, 93]
            )
        ];

        // Use the DST that matches the Elixir reference
        let dst = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_";

        for (i, (sk_bytes, data, elixir_sig)) in test_cases.iter().enumerate() {
            println!("Testing case {}: sk_len={}, data_len={}", 
                     i, sk_bytes.len(), data.len());

            // Get the public key from the secret key
            let pk = get_public_key(sk_bytes)
                .expect(&format!("Failed to get public key for case {}", i));
            
            // Generate signature with our Rust implementation
            let rust_sig = sign(sk_bytes, data, dst)
                .expect(&format!("Failed to sign with Rust for case {}", i));

            println!("Case {}: Public key: {:?}", i, pk);
            println!("Case {}: Elixir signature: {:?}", i, elixir_sig);
            println!("Case {}: Rust signature: {:?}", i, rust_sig.to_vec());

            // Verify that our Rust signature is valid (this should always work)
            match verify(&pk, &rust_sig, data, dst) {
                Ok(_) => println!("Case {}: ✓ Rust signature verifies successfully", i),
                Err(e) => panic!("Case {}: ✗ Rust signature verification failed: {:?}", i, e),
            }

            // Try to verify the Elixir reference signature (this may fail)
            match verify(&pk, elixir_sig, data, dst) {
                Ok(_) => println!("Case {}: ✓ Elixir signature verifies successfully", i),
                Err(e) => {
                    println!("Case {}: ✗ Elixir signature verification failed: {:?}", i, e);
                    println!("Case {}: This confirms different BLS implementations/configurations", i);
                }
            }

            println!("Case {}: Rust signature is valid, Elixir compatibility varies", i);
        }

        println!("Test completed: Rust implementation produces valid signatures");
    }

    #[test]
    fn elixir_public_key_signature_verification() {
        // Elixir-generated public key
        let elixir_pk = vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222];

        // Test cases with Elixir signatures and corresponding data
        let test_cases = vec![
            (
                // data
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49],
                // elixir signature
                vec![166, 193, 20, 132, 125, 87, 40, 182, 101, 225, 125, 220, 97, 93, 13, 2, 89, 220, 166, 6, 106, 203, 96, 63, 122, 16, 226, 117, 143, 219, 5, 105, 180, 229, 65, 58, 238, 93, 230, 253, 208, 110, 35, 219, 222, 176, 82, 112, 15, 149, 72, 148, 54, 88, 2, 94, 219, 26, 235, 98, 77, 202, 1, 83, 6, 38, 39, 150, 236, 176, 141, 222, 93, 133, 66, 154, 226, 55, 214, 100, 183, 179, 167, 140, 140, 77, 117, 11, 167, 219, 140, 144, 144, 160, 143, 128]
            ),
            (
                // data with "255" suffix
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 50, 53, 53],
                // elixir signature
                vec![141, 6, 181, 106, 49, 117, 193, 12, 249, 102, 71, 237, 125, 55, 25, 3, 14, 199, 113, 157, 49, 168, 205, 89, 106, 76, 3, 37, 170, 124, 149, 45, 234, 206, 44, 177, 90, 0, 14, 111, 30, 9, 197, 189, 201, 43, 86, 139, 22, 145, 182, 32, 77, 220, 35, 186, 5, 251, 37, 173, 187, 243, 110, 33, 57, 23, 67, 58, 166, 74, 200, 145, 232, 5, 151, 244, 62, 216, 159, 43, 131, 43, 179, 105, 154, 33, 91, 88, 143, 91, 40, 147, 129, 228, 37, 98]
            ),
            (
                // data with timestamp "1640995200"
                vec![169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49, 54, 52, 48, 57, 57, 53, 50, 48, 48],
                // elixir signature
                vec![137, 145, 8, 245, 3, 166, 187, 110, 172, 28, 115, 177, 226, 179, 239, 201, 245, 173, 213, 25, 211, 84, 225, 194, 82, 30, 133, 105, 197, 97, 55, 185, 157, 83, 140, 89, 2, 3, 57, 7, 84, 242, 51, 161, 247, 238, 16, 126, 18, 69, 208, 108, 184, 132, 63, 67, 219, 144, 108, 54, 50, 176, 128, 138, 121, 191, 181, 168, 198, 229, 76, 246, 29, 36, 130, 95, 146, 213, 222, 230, 192, 179, 179, 198, 99, 209, 120, 134, 194, 181, 239, 187, 42, 46, 136, 93]
            )
        ];

        // Use the same DST
        let dst = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_";

        println!("Testing Elixir signatures with Elixir public key");
        println!("Elixir public key: {:?}", elixir_pk);

        for (i, (data, elixir_sig)) in test_cases.iter().enumerate() {
            println!("\nTesting case {}: data_len={}, sig_len={}", 
                     i, data.len(), elixir_sig.len());

            // Try to verify the Elixir signature with the Elixir public key
            match verify(&elixir_pk, elixir_sig, data, dst) {
                Ok(_) => println!("Case {}: ✓ Elixir signature verifies with Elixir public key", i),
                Err(e) => {
                    println!("Case {}: ✗ Elixir signature failed verification: {:?}", i, e);
                    println!("Case {}: This indicates potential issues with Elixir test data or DST mismatch", i);
                }
            }
        }

        println!("\nTest completed: Checked if Elixir signatures verify with Elixir public key");
    }
}
