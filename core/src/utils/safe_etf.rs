use eetf::{Atom, Map, Term};
use std::cmp::Ordering;
use std::collections::HashMap;

/// Encode an EETF term using small atoms (tag 119) instead of legacy atoms (tag 100)
/// This ensures compatibility with Elixir's [:safe] option which rejects old atom encoding
pub fn encode_safe(term: &Term) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(131); // ETF version marker
    encode_term_with_small_atoms(term, &mut buf);
    buf
}

/// Encode an EETF with small atoms ([:safe]) and [:deterministic]
pub fn encode_safe_deterministic(term: &Term) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(131); // ETF version marker
    encode_map_safe_deterministic(term, &mut buf);
    buf
}

/// Encode a map with predictable key ordering based on provided key names
/// Keys not present in the map are silently skipped
/// This function ensures deterministic serialization regardless of HashMap's internal ordering
pub fn encode_map_with_ordered_keys(map: &Map, key_order: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(131); // ETF version marker
    encode_map_with_key_order(&map.map, key_order, &mut buf);
    buf
}

/// Encode just the map part with ordered keys (without ETF version marker)
/// This is useful when encoding a map as part of a larger structure
pub fn encode_map_with_key_order(map: &HashMap<Term, Term>, key_order: &[&str], buf: &mut Vec<u8>) {
    // Collect present key-value pairs in the specified order
    let mut present_pairs = Vec::new();

    for &key_name in key_order {
        let key_atom = Term::Atom(Atom::from(key_name));
        if let Some(value) = map.get(&key_atom) {
            present_pairs.push((key_atom, value));
        }
    }

    // Write map header with the actual count of present key-value pairs
    buf.push(116); // map tag
    buf.extend_from_slice(&(present_pairs.len() as u32).to_be_bytes());

    // Encode the key-value pairs in the specified order
    for (key, value) in present_pairs {
        encode_term_with_small_atoms(&key, buf);
        encode_term_with_small_atoms(value, buf);
    }
}

/// Compare two terms according to Erlang's term ordering hierarchy
fn compare_terms(a: &Term, b: &Term) -> Ordering {
    let type_order = |term: &Term| -> u8 {
        match term {
            Term::FixInteger(_) | Term::BigInteger(_) | Term::Float(_) => 1, // Numbers
            Term::Atom(_) => 2,                                              // Atoms
            Term::Reference(_) => 3,                                         // References
            Term::Port(_) => 4,                                              // Ports
            Term::Pid(_) => 5,                                               // PIDs
            Term::Tuple(_) => 6,                                             // Tuples
            Term::Map(_) => 7,                                               // Maps
            Term::List(_) | Term::ImproperList(_) => 8,                      // Lists
            Term::Binary(_) | Term::BitBinary(_) | Term::ByteList(_) => 9,   // Binaries
            Term::ExternalFun(_) | Term::InternalFun(_) => 10,               // Functions (after binaries)
        }
    };

    let a_type = type_order(a);
    let b_type = type_order(b);

    match a_type.cmp(&b_type) {
        Ordering::Equal => {
            match (a, b) {
                // Numbers: within number types, compare by numeric value
                // But integers come before floats in ETF ordering
                (Term::FixInteger(a_int), Term::FixInteger(b_int)) => a_int.value.cmp(&b_int.value),
                (Term::BigInteger(a_big), Term::BigInteger(b_big)) => a_big.value.cmp(&b_big.value),
                (Term::Float(a_float), Term::Float(b_float)) => {
                    a_float.value.partial_cmp(&b_float.value).unwrap_or(Ordering::Equal)
                }

                // Mixed number types: integers should come before floats in ETF format
                (Term::FixInteger(_), Term::Float(_)) => Ordering::Less,
                (Term::Float(_), Term::FixInteger(_)) => Ordering::Greater,
                (Term::BigInteger(_), Term::Float(_)) => Ordering::Less,
                (Term::Float(_), Term::BigInteger(_)) => Ordering::Greater,
                (Term::FixInteger(_), Term::BigInteger(_)) => Ordering::Less, // small int before big int
                (Term::BigInteger(_), Term::FixInteger(_)) => Ordering::Greater,

                // Atoms: compare alphabetically
                (Term::Atom(a_atom), Term::Atom(b_atom)) => a_atom.name.cmp(&b_atom.name),

                // Binaries: lexicographic byte comparison
                (Term::Binary(a_bin), Term::Binary(b_bin)) => a_bin.bytes.cmp(&b_bin.bytes),
                (Term::ByteList(a_bytes), Term::ByteList(b_bytes)) => a_bytes.bytes.cmp(&b_bytes.bytes),

                // For other types within the same category, use string representation as fallback
                _ => format!("{:?}", a).cmp(&format!("{:?}", b)),
            }
        }
        other => other,
    }
}

/// Encode a term with deterministic ordering (maps have sorted keys)
fn encode_map_safe_deterministic(term: &Term, buf: &mut Vec<u8>) {
    match term {
        Term::Map(map) => {
            // Sort keys according to Erlang term ordering
            let mut sorted_pairs: Vec<_> = map.map.iter().collect();
            sorted_pairs.sort_by(|(a, _), (b, _)| compare_terms(a, b));

            buf.push(116); // map tag
            buf.extend_from_slice(&(sorted_pairs.len() as u32).to_be_bytes());

            for (key, value) in sorted_pairs {
                encode_map_safe_deterministic(key, buf);
                encode_map_safe_deterministic(value, buf);
            }
        }
        _ => {
            // For non-map terms, use the small atoms encoding but recurse with deterministic encoding for nested terms
            encode_term_safe_deterministic(term, buf);
        }
    }
}

/// Encode term with small atoms and deterministic ordering for nested structures
fn encode_term_safe_deterministic(term: &Term, buf: &mut Vec<u8>) {
    match term {
        Term::Atom(atom) => {
            // Use small atom (tag 119) instead of legacy atom (tag 100)
            let name_bytes = atom.name.as_bytes();
            if name_bytes.len() <= 255 {
                buf.push(119); // small atom
                buf.push(name_bytes.len() as u8);
                buf.extend_from_slice(name_bytes);
            } else {
                // For atoms longer than 255 bytes, use atom_utf8 (tag 118)
                buf.push(118); // atom_utf8
                buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(name_bytes);
            }
        }
        Term::List(list) => {
            if list.elements.is_empty() {
                buf.push(106); // nil
            } else {
                buf.push(108); // list
                buf.extend_from_slice(&(list.elements.len() as u32).to_be_bytes());
                for element in &list.elements {
                    encode_map_safe_deterministic(element, buf); // Recurse with deterministic ordering
                }
                buf.push(106); // tail (nil)
            }
        }
        Term::ImproperList(improper) => {
            buf.push(108); // list
            buf.extend_from_slice(&(improper.elements.len() as u32).to_be_bytes());
            for element in &improper.elements {
                encode_map_safe_deterministic(element, buf); // Recurse with deterministic ordering
            }
            encode_map_safe_deterministic(&improper.last, buf); // tail
        }
        Term::Tuple(tuple) => {
            if tuple.elements.len() <= 255 {
                buf.push(104); // small_tuple
                buf.push(tuple.elements.len() as u8);
            } else {
                buf.push(105); // large_tuple
                buf.extend_from_slice(&(tuple.elements.len() as u32).to_be_bytes());
            }
            for element in &tuple.elements {
                encode_map_safe_deterministic(element, buf); // Recurse with deterministic ordering
            }
        }
        Term::Map(_map) => {
            // This shouldn't happen as maps are handled in encode_term_deterministic
            // But handle it anyway for safety
            encode_map_safe_deterministic(term, buf);
        }
        _ => {
            // For all other types, use the existing small atoms encoding
            encode_term_with_small_atoms(term, buf);
        }
    }
}

fn encode_term_with_small_atoms(term: &Term, buf: &mut Vec<u8>) {
    match term {
        Term::Atom(atom) => {
            // Use small atom (tag 119) instead of legacy atom (tag 100)
            let name_bytes = atom.name.as_bytes();
            if name_bytes.len() <= 255 {
                buf.push(119); // small atom
                buf.push(name_bytes.len() as u8);
                buf.extend_from_slice(name_bytes);
            } else {
                // For atoms longer than 255 bytes, use atom_utf8 (tag 118)
                buf.push(118); // atom_utf8
                buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(name_bytes);
            }
        }
        Term::Binary(binary) => {
            buf.push(109); // binary
            buf.extend_from_slice(&(binary.bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&binary.bytes);
        }
        Term::FixInteger(fix_int) => {
            if fix_int.value >= 0 && fix_int.value <= 255 {
                buf.push(97); // small_integer
                buf.push(fix_int.value as u8);
            } else {
                buf.push(98); // integer
                buf.extend_from_slice(&fix_int.value.to_be_bytes());
            }
        }
        Term::BigInteger(big_int) => {
            // Convert big integer to bytes representation (little-endian for ETF format)
            let bytes = big_int.value.to_bytes_le().1;
            if bytes.len() <= 255 {
                buf.push(110); // small_big
                buf.push(bytes.len() as u8);
                buf.push(if big_int.value >= 0.into() { 0 } else { 1 }); // sign
            } else {
                buf.push(111); // large_big
                buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buf.push(if big_int.value >= 0.into() { 0 } else { 1 }); // sign
            }
            buf.extend_from_slice(&bytes);
        }
        Term::List(list) => {
            if list.elements.is_empty() {
                buf.push(106); // nil
            } else {
                buf.push(108); // list
                buf.extend_from_slice(&(list.elements.len() as u32).to_be_bytes());
                for element in &list.elements {
                    encode_term_with_small_atoms(element, buf);
                }
                buf.push(106); // tail (nil)
            }
        }
        Term::ImproperList(improper) => {
            buf.push(108); // list
            buf.extend_from_slice(&(improper.elements.len() as u32).to_be_bytes());
            for element in &improper.elements {
                encode_term_with_small_atoms(element, buf);
            }
            encode_term_with_small_atoms(&improper.last, buf); // tail
        }
        Term::Tuple(tuple) => {
            if tuple.elements.len() <= 255 {
                buf.push(104); // small_tuple
                buf.push(tuple.elements.len() as u8);
            } else {
                buf.push(105); // large_tuple
                buf.extend_from_slice(&(tuple.elements.len() as u32).to_be_bytes());
            }
            for element in &tuple.elements {
                encode_term_with_small_atoms(element, buf);
            }
        }
        Term::Map(map) => {
            buf.push(116); // map
            buf.extend_from_slice(&(map.map.len() as u32).to_be_bytes());
            for (key, value) in &map.map {
                encode_term_with_small_atoms(key, buf);
                encode_term_with_small_atoms(value, buf);
            }
        }
        Term::Pid(pid) => {
            buf.push(103); // pid
            encode_term_with_small_atoms(&Term::Atom(pid.node.clone()), buf);
            buf.extend_from_slice(&pid.id.to_be_bytes());
            buf.extend_from_slice(&pid.serial.to_be_bytes());
            buf.push(pid.creation.try_into().unwrap());
        }
        Term::Port(port) => {
            buf.push(102); // port
            encode_term_with_small_atoms(&Term::Atom(port.node.clone()), buf);
            buf.extend_from_slice(&port.id.to_be_bytes());
            buf.push(port.creation.try_into().unwrap());
        }
        Term::Reference(reference) => {
            buf.push(114); // new_reference
            buf.extend_from_slice(&(reference.id.len() as u16).to_be_bytes());
            encode_term_with_small_atoms(&Term::Atom(reference.node.clone()), buf);
            buf.push(reference.creation.try_into().unwrap());
            for id in &reference.id {
                buf.extend_from_slice(&id.to_be_bytes());
            }
        }
        Term::ExternalFun(ext_fun) => {
            buf.push(113); // export
            encode_term_with_small_atoms(&Term::Atom(ext_fun.module.clone()), buf);
            encode_term_with_small_atoms(&Term::Atom(ext_fun.function.clone()), buf);
            encode_term_with_small_atoms(&Term::FixInteger(eetf::FixInteger { value: ext_fun.arity as i32 }), buf);
        }
        Term::InternalFun(int_fun) => {
            match int_fun.as_ref() {
                eetf::InternalFun::Old { module, pid, free_vars, index, uniq } => {
                    buf.push(117); // fun (old representation) 
                    buf.extend_from_slice(&(*index as u32).to_be_bytes());
                    buf.extend_from_slice(&(*uniq as u32).to_be_bytes());
                    encode_term_with_small_atoms(&Term::Atom(module.clone()), buf);
                    encode_term_with_small_atoms(&Term::Pid(pid.clone()), buf);
                    for var in free_vars {
                        encode_term_with_small_atoms(var, buf);
                    }
                }
                eetf::InternalFun::New { module, arity, pid, free_vars, index, uniq, old_index, old_uniq } => {
                    buf.push(112); // fun (new representation)
                    buf.push(*arity);
                    buf.extend_from_slice(uniq);
                    buf.extend_from_slice(&index.to_be_bytes());
                    buf.extend_from_slice(&(free_vars.len() as u32).to_be_bytes());
                    encode_term_with_small_atoms(&Term::Atom(module.clone()), buf);
                    encode_term_with_small_atoms(&Term::FixInteger(eetf::FixInteger { value: *old_index }), buf);
                    encode_term_with_small_atoms(&Term::FixInteger(eetf::FixInteger { value: *old_uniq }), buf);
                    encode_term_with_small_atoms(&Term::Pid(pid.clone()), buf);
                    for var in free_vars {
                        encode_term_with_small_atoms(var, buf);
                    }
                }
            }
        }
        Term::BitBinary(bit_binary) => {
            buf.push(77); // bit_binary
            buf.extend_from_slice(&(bit_binary.bytes.len() as u32).to_be_bytes());
            buf.push(bit_binary.tail_bits_size);
            buf.extend_from_slice(&bit_binary.bytes);
        }
        Term::Float(float) => {
            buf.push(70); // new_float
            buf.extend_from_slice(&float.value.to_be_bytes());
        }
        Term::ByteList(byte_list) => {
            buf.push(107); // string
            buf.extend_from_slice(&(byte_list.bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(&byte_list.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eetf::{Atom, FixInteger, Map};
    use std::collections::HashMap;

    #[test]
    fn test_small_atom_encoding() {
        let atom = Term::Atom(Atom::from("test"));
        let encoded = encode_safe(&atom);

        // Should start with ETF version (131) and small atom tag (119)
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 119); // small atom tag
        assert_eq!(encoded[2], 4); // length of "test"
        assert_eq!(&encoded[3..7], b"test");
    }

    #[test]
    fn test_map_with_small_atoms() {
        let mut map = HashMap::new();
        map.insert(Term::Atom(Atom::from("key")), Term::Atom(Atom::from("value")));
        let term_map = Term::Map(Map { map });

        let encoded = encode_safe(&term_map);

        // Should start with ETF version (131) and map tag (116)
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 116); // map tag

        // Should contain small atom tags (119) for both key and value atoms
        assert!(encoded.contains(&119)); // small atom tag should appear
    }

    #[test]
    fn test_big_integer_encoding() {
        use eetf::BigInteger;

        // Test values that require BigInteger encoding
        let test_values = vec![
            2147483648u64, // i32::MAX + 1
            4294967296u64, // u32::MAX + 1
            1693958400u64, // Typical Unix timestamp
        ];

        for value in test_values {
            let big_int_term = Term::BigInteger(BigInteger::from(value));

            // Encode with original method
            let mut original_encoded = Vec::new();
            big_int_term.encode(&mut original_encoded).unwrap();

            // Encode with our method
            let our_encoded = encode_safe(&big_int_term);

            // Both should produce identical bytes
            assert_eq!(original_encoded, our_encoded, "Encoding mismatch for value {}", value);

            // Both should decode to the same value
            let original_decoded = Term::decode(&original_encoded[..]).unwrap();
            let our_decoded = Term::decode(&our_encoded[..]).unwrap();

            if let (Term::BigInteger(orig), Term::BigInteger(ours)) = (&original_decoded, &our_decoded) {
                assert_eq!(orig.value, ours.value, "BigInteger values should match for {}", value);
            }
        }
    }

    #[test]
    fn test_compatibility_with_original() {
        // Test that our encoding produces the same structure as the original,
        // except atoms use tag 119 instead of 100
        let atom = Term::Atom(Atom::from("test"));
        let mut original_encoded = Vec::new();
        atom.encode(&mut original_encoded).unwrap();
        let our_encoded = encode_safe(&atom);

        println!("Original: {:?}", original_encoded);
        println!("Our:      {:?}", our_encoded);

        // Both should start with ETF version
        assert_eq!(original_encoded[0], our_encoded[0]); // ETF version (131)

        if original_encoded.len() == 8 && our_encoded.len() == 7 {
            // Original uses legacy atom (100) with 2-byte length, ours uses small atom (119) with 1-byte length
            assert_eq!(original_encoded[1], 100); // legacy atom  
            assert_eq!(our_encoded[1], 119); // small atom

            // For legacy atoms, the length is 2 bytes, for small atoms it's 1 byte
            // original: [131, 100, 0, 4, 't', 'e', 's', 't']
            // ours:     [131, 119, 4, 't', 'e', 's', 't']
            assert_eq!(original_encoded[2], 0); // high byte of length (should be 0 for short strings)
            assert_eq!(original_encoded[3], 4); // low byte of length
            assert_eq!(our_encoded[2], 4); // single byte length

            // String content should be the same
            assert_eq!(original_encoded[4..], our_encoded[3..]);
        } else {
            // Fallback to original test logic if lengths are different than expected
            assert_eq!(original_encoded.len(), our_encoded.len());
            assert_eq!(original_encoded[1], 100); // legacy atom
            assert_eq!(our_encoded[1], 119); // small atom
            assert_eq!(original_encoded[2..], our_encoded[2..]);
        }
    }

    #[test]
    fn test_ordered_map_serialization() {
        // Create a map with multiple key-value pairs
        let mut map_data = HashMap::new();
        map_data.insert(Term::Atom(Atom::from("zebra")), Term::FixInteger(FixInteger { value: 3 }));
        map_data.insert(Term::Atom(Atom::from("alpha")), Term::FixInteger(FixInteger { value: 1 }));
        map_data.insert(Term::Atom(Atom::from("beta")), Term::FixInteger(FixInteger { value: 2 }));

        let map = Map { map: map_data };

        // Define key order - different from natural HashMap order
        let key_order = ["alpha", "beta", "zebra"];

        // Encode with ordered keys
        let encoded = encode_map_with_ordered_keys(&map, &key_order);

        // Verify ETF structure
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 116); // map tag

        // Should have 3 pairs (encoded as 4 bytes: 0, 0, 0, 3)
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 0);
        assert_eq!(encoded[4], 0);
        assert_eq!(encoded[5], 3);

        // Decode and verify the order is preserved
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            // Convert back to ordered pairs to verify order
            let key_order_terms: Vec<Term> = key_order.iter().map(|&k| Term::Atom(Atom::from(k))).collect();

            // Verify all expected keys are present
            for expected_key in &key_order_terms {
                assert!(decoded_map.map.contains_key(expected_key));
            }
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_ordered_map_with_missing_keys() {
        // Create a map with only some of the keys we'll request
        let mut map_data = HashMap::new();
        map_data.insert(Term::Atom(Atom::from("existing_key")), Term::FixInteger(FixInteger { value: 42 }));
        map_data.insert(Term::Atom(Atom::from("another_key")), Term::FixInteger(FixInteger { value: 100 }));

        let map = Map { map: map_data };

        // Define key order that includes keys not in the map
        let key_order = ["missing_key1", "existing_key", "missing_key2", "another_key", "missing_key3"];

        // Encode with ordered keys
        let encoded = encode_map_with_ordered_keys(&map, &key_order);

        // Verify ETF structure
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 116); // map tag

        // Should have only 2 pairs (encoded as 4 bytes: 0, 0, 0, 2) since missing keys are skipped
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 0);
        assert_eq!(encoded[4], 0);
        assert_eq!(encoded[5], 2);

        // Decode and verify only existing keys are present
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 2);
            assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from("existing_key"))));
            assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from("another_key"))));
            assert!(!decoded_map.map.contains_key(&Term::Atom(Atom::from("missing_key1"))));
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_empty_map_ordered_serialization() {
        // Create an empty map
        let map = Map { map: HashMap::new() };
        let key_order = ["any_key", "another_key"];

        // Encode with ordered keys
        let encoded = encode_map_with_ordered_keys(&map, &key_order);

        // Verify ETF structure for empty map
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 116); // map tag

        // Should have 0 pairs (encoded as 4 bytes: 0, 0, 0, 0)
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 0);
        assert_eq!(encoded[4], 0);
        assert_eq!(encoded[5], 0);

        // Decode and verify it's an empty map
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 0);
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_ordering() {
        // Create the same map multiple times and ensure consistent serialization
        let create_map = || {
            let mut map_data = HashMap::new();
            map_data.insert(Term::Atom(Atom::from("z")), Term::FixInteger(FixInteger { value: 1 }));
            map_data.insert(Term::Atom(Atom::from("a")), Term::FixInteger(FixInteger { value: 2 }));
            map_data.insert(Term::Atom(Atom::from("m")), Term::FixInteger(FixInteger { value: 3 }));
            Map { map: map_data }
        };

        let key_order = ["z", "m", "a"]; // Specific order

        // Encode the same map structure multiple times
        let encoded1 = encode_map_with_ordered_keys(&create_map(), &key_order);
        let encoded2 = encode_map_with_ordered_keys(&create_map(), &key_order);
        let encoded3 = encode_map_with_ordered_keys(&create_map(), &key_order);

        // All encodings should be identical (deterministic)
        assert_eq!(encoded1, encoded2);
        assert_eq!(encoded2, encoded3);
        assert_eq!(encoded1, encoded3);
    }

    #[test]
    fn test_map_with_key_order_function() {
        // Test the lower-level function that doesn't add ETF version marker
        let mut map_data = HashMap::new();
        map_data.insert(Term::Atom(Atom::from("first")), Term::FixInteger(FixInteger { value: 1 }));
        map_data.insert(Term::Atom(Atom::from("second")), Term::FixInteger(FixInteger { value: 2 }));

        let key_order = ["second", "first"];
        let mut buf = Vec::new();

        // Add ETF version manually
        buf.push(131);
        encode_map_with_key_order(&map_data, &key_order, &mut buf);

        // Should be decodable
        let decoded = Term::decode(&buf[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 2);
            assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from("first"))));
            assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from("second"))));
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_encoding_mixed_key_types() {
        // Test deterministic encoding with mixed key types following Erlang's hierarchy
        let mut map_data = HashMap::new();

        // Add keys in different order than they should be sorted
        map_data.insert(Term::Atom(Atom::from("atom_key")), Term::FixInteger(FixInteger { value: 1 })); // Atoms (type 2)
        map_data.insert(
            Term::Binary(eetf::Binary { bytes: b"binary_key".to_vec() }),
            Term::FixInteger(FixInteger { value: 2 }),
        ); // Binaries (type 9)
        map_data.insert(Term::FixInteger(FixInteger { value: 42 }), Term::FixInteger(FixInteger { value: 3 })); // Numbers (type 1)

        let map = Term::Map(Map { map: map_data });

        // Encode with deterministic ordering
        let encoded = encode_safe_deterministic(&map);

        // Verify it's properly encoded ETF
        assert_eq!(encoded[0], 131); // ETF version
        assert_eq!(encoded[1], 116); // map tag

        // Should be decodable
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 3);

            // Verify all keys are present
            assert!(decoded_map.map.contains_key(&Term::FixInteger(FixInteger { value: 42 })));
            assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from("atom_key"))));
            assert!(decoded_map.map.contains_key(&Term::Binary(eetf::Binary { bytes: b"binary_key".to_vec() })));
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_encoding_atom_alphabetical_order() {
        // Test that atoms are sorted alphabetically within their type
        let mut map_data = HashMap::new();

        // Add atom keys in reverse alphabetical order
        map_data.insert(Term::Atom(Atom::from("zebra")), Term::FixInteger(FixInteger { value: 1 }));
        map_data.insert(Term::Atom(Atom::from("apple")), Term::FixInteger(FixInteger { value: 2 }));
        map_data.insert(Term::Atom(Atom::from("banana")), Term::FixInteger(FixInteger { value: 3 }));

        let map = Term::Map(Map { map: map_data });

        // Encode with deterministic ordering - should be consistent
        let encoded1 = encode_safe_deterministic(&map);
        let encoded2 = encode_safe_deterministic(&map);

        // Multiple encodings should be identical (deterministic)
        assert_eq!(encoded1, encoded2);

        // Should be decodable
        let decoded = Term::decode(&encoded1[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 3);
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_encoding_number_ordering() {
        // Test that numbers are ordered by value, not type
        let mut map_data = HashMap::new();

        // Add different number types
        map_data.insert(Term::FixInteger(FixInteger { value: 100 }), Term::Atom(Atom::from("hundred")));
        map_data.insert(Term::FixInteger(FixInteger { value: 5 }), Term::Atom(Atom::from("five")));
        map_data.insert(Term::FixInteger(FixInteger { value: 50 }), Term::Atom(Atom::from("fifty")));

        let map = Term::Map(Map { map: map_data });

        let encoded = encode_safe_deterministic(&map);

        // Should be decodable and deterministic
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), 3);
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_vs_original_compatibility() {
        // Test that deterministic encoding uses small atoms like the original function
        let atom = Term::Atom(Atom::from("test_atom"));

        let deterministic_encoded = encode_safe_deterministic(&atom);
        let small_atoms_encoded = encode_safe(&atom);

        // Should be identical for simple atoms
        assert_eq!(deterministic_encoded, small_atoms_encoded);

        // Both should use small atom tag (119)
        assert_eq!(deterministic_encoded[1], 119); // small atom tag
        assert_eq!(small_atoms_encoded[1], 119); // small atom tag
    }

    #[test]
    fn test_deterministic_encoding_anr_keys() {
        // Test the specific ANR keys mentioned in the specification
        let mut map_data = HashMap::new();

        // Add ANR keys in original order
        let anr_keys = ["ip4", "pk", "pop", "port", "signature", "ts", "version", "anr_name", "anr_desc"];
        for (i, key) in anr_keys.iter().enumerate() {
            map_data.insert(Term::Atom(Atom::from(*key)), Term::FixInteger(FixInteger { value: i as i32 }));
        }

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Should be deterministic across multiple calls
        let encoded2 = encode_safe_deterministic(&map);
        assert_eq!(encoded, encoded2);

        // Should be decodable
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            assert_eq!(decoded_map.map.len(), anr_keys.len());

            // All keys should be present
            for key in &anr_keys {
                assert!(decoded_map.map.contains_key(&Term::Atom(Atom::from(*key))));
            }
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_deterministic_encoding_nested_structures() {
        // Test that nested maps and lists also get deterministic encoding
        let mut inner_map = HashMap::new();
        inner_map.insert(Term::Atom(Atom::from("z")), Term::FixInteger(FixInteger { value: 1 }));
        inner_map.insert(Term::Atom(Atom::from("a")), Term::FixInteger(FixInteger { value: 2 }));

        let mut outer_map = HashMap::new();
        outer_map.insert(Term::Atom(Atom::from("nested")), Term::Map(Map { map: inner_map }));
        outer_map.insert(
            Term::Atom(Atom::from("list")),
            Term::List(eetf::List {
                elements: vec![Term::Atom(Atom::from("second")), Term::Atom(Atom::from("first"))],
            }),
        );

        let map = Term::Map(Map { map: outer_map });

        let encoded1 = encode_safe_deterministic(&map);
        let encoded2 = encode_safe_deterministic(&map);

        // Should be deterministic
        assert_eq!(encoded1, encoded2);

        // Should be decodable
        let decoded = Term::decode(&encoded1[..]).unwrap();
        if let Term::Map(_) = decoded {
            // Successfully decoded
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_compare_terms_ordering() {
        use super::compare_terms;

        // Test type hierarchy: Numbers < Atoms < ... < Binaries
        let number = Term::FixInteger(FixInteger { value: 42 });
        let atom = Term::Atom(Atom::from("test"));
        let binary = Term::Binary(eetf::Binary { bytes: b"test".to_vec() });

        // Numbers should come before atoms
        assert_eq!(compare_terms(&number, &atom), Ordering::Less);
        assert_eq!(compare_terms(&atom, &number), Ordering::Greater);

        // Atoms should come before binaries
        assert_eq!(compare_terms(&atom, &binary), Ordering::Less);
        assert_eq!(compare_terms(&binary, &atom), Ordering::Greater);

        // Numbers should come before binaries
        assert_eq!(compare_terms(&number, &binary), Ordering::Less);
        assert_eq!(compare_terms(&binary, &number), Ordering::Greater);

        // Same types should compare by value
        let atom1 = Term::Atom(Atom::from("apple"));
        let atom2 = Term::Atom(Atom::from("zebra"));
        assert_eq!(compare_terms(&atom1, &atom2), Ordering::Less);
        assert_eq!(compare_terms(&atom2, &atom1), Ordering::Greater);
        assert_eq!(compare_terms(&atom1, &atom1), Ordering::Equal);
    }

    #[test]
    fn test_deterministic_encoding_byte_order_verification() {
        // Test that the actual byte encoding follows the correct order
        let mut map_data = HashMap::new();

        // Add keys in reverse order of how they should appear in encoding
        map_data.insert(
            Term::Binary(eetf::Binary { bytes: b"binary".to_vec() }),
            Term::FixInteger(FixInteger { value: 3 }),
        ); // Should be last (type 9)
        map_data.insert(Term::Atom(Atom::from("zebra")), Term::FixInteger(FixInteger { value: 2 })); // Should be middle (type 2, but "zebra" comes after "apple")
        map_data.insert(Term::Atom(Atom::from("apple")), Term::FixInteger(FixInteger { value: 1 })); // Should be second (type 2, "apple" comes first alphabetically)
        map_data.insert(Term::FixInteger(FixInteger { value: 42 }), Term::FixInteger(FixInteger { value: 0 })); // Should be first (type 1)

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Decode and extract the keys in their encoded order
        let decoded = Term::decode(&encoded[..]).unwrap();
        if let Term::Map(decoded_map) = decoded {
            // Convert to Vec to check order (HashMap doesn't preserve order, but we can check the encoding bytes)
            let mut found_keys = Vec::new();
            for key in decoded_map.map.keys() {
                found_keys.push(key.clone());
            }

            // We need to check the actual bytes to verify order since HashMap loses order
            // Let's manually parse the encoded bytes to verify key ordering

            // Skip ETF version (1 byte) + map tag (1 byte) + map size (4 bytes) = 6 bytes
            let mut pos = 6;
            let mut encoded_keys = Vec::new();

            // Parse each key-value pair from the encoded bytes
            for _ in 0..4 {
                // We know we have 4 pairs
                let key_start = pos;

                // Parse the key to find where it ends
                match encoded[pos] {
                    119 => {
                        // small atom
                        let len = encoded[pos + 1] as usize;
                        pos += 2 + len; // tag + length + atom bytes
                    }
                    109 => {
                        // binary
                        let len = u32::from_be_bytes([
                            encoded[pos + 1],
                            encoded[pos + 2],
                            encoded[pos + 3],
                            encoded[pos + 4],
                        ]) as usize;
                        pos += 5 + len; // tag + length (4 bytes) + binary bytes
                    }
                    97 => {
                        // small integer
                        pos += 2; // tag + value
                    }
                    98 => {
                        // integer
                        pos += 5; // tag + value (4 bytes)
                    }
                    _ => panic!("Unexpected key type in encoded data"),
                }

                let key_end = pos;
                encoded_keys.push(&encoded[key_start..key_end]);

                // Skip the value to get to next key
                match encoded[pos] {
                    97 => pos += 2, // small integer value
                    98 => pos += 5, // integer value
                    _ => panic!("Unexpected value type in encoded data"),
                }
            }

            // Verify the keys appear in the correct order in the encoded bytes:
            // 1. Number (42) - should be first
            // 2. Atom "apple" - should be second
            // 3. Atom "zebra" - should be third
            // 4. Binary "binary" - should be fourth

            // Check first key is the number 42
            assert_eq!(encoded_keys[0][0], 97); // small integer tag
            assert_eq!(encoded_keys[0][1], 42); // value 42

            // Check second key is atom "apple"
            assert_eq!(encoded_keys[1][0], 119); // small atom tag
            assert_eq!(encoded_keys[1][1], 5); // length of "apple"
            assert_eq!(&encoded_keys[1][2..7], b"apple");

            // Check third key is atom "zebra"
            assert_eq!(encoded_keys[2][0], 119); // small atom tag
            assert_eq!(encoded_keys[2][1], 5); // length of "zebra"  
            assert_eq!(&encoded_keys[2][2..7], b"zebra");

            // Check fourth key is binary "binary"
            assert_eq!(encoded_keys[3][0], 109); // binary tag
            // Length is 4 bytes big-endian: [0, 0, 0, 6] for "binary"
            assert_eq!(&encoded_keys[3][1..5], &[0, 0, 0, 6]);
            assert_eq!(&encoded_keys[3][5..11], b"binary");
        } else {
            panic!("Decoded term is not a map");
        }
    }

    #[test]
    fn test_anr_keys_correct_alphabetical_order() {
        // Test that ANR keys are encoded in correct alphabetical order as per spec
        let mut map_data = HashMap::new();

        // Add ANR keys in the original order (not alphabetical)
        let anr_keys = ["ip4", "pk", "pop", "port", "signature", "ts", "version", "anr_name", "anr_desc"];
        for (i, key) in anr_keys.iter().enumerate() {
            map_data.insert(Term::Atom(Atom::from(*key)), Term::FixInteger(FixInteger { value: i as i32 }));
        }

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Parse the encoded bytes to extract keys in their actual encoded order
        let mut pos = 6; // Skip ETF version + map tag + map size
        let mut actual_key_order = Vec::new();

        for _ in 0..anr_keys.len() {
            // Parse atom key
            if encoded[pos] == 119 {
                // small atom tag
                let len = encoded[pos + 1] as usize;
                let atom_name = std::str::from_utf8(&encoded[pos + 2..pos + 2 + len]).unwrap();
                actual_key_order.push(atom_name.to_string());
                pos += 2 + len; // Skip key

                // Skip value (small integer)
                pos += 2; // tag + value
            } else {
                panic!("Expected atom key, found tag: {}", encoded[pos]);
            }
        }

        // Expected order according to Erlang/Elixir alphabetical sorting
        let expected_order = ["anr_desc", "anr_name", "ip4", "pk", "pop", "port", "signature", "ts", "version"];

        assert_eq!(
            actual_key_order, expected_order,
            "ANR keys should be in alphabetical order: {:?}, but got: {:?}",
            expected_order, actual_key_order
        );
    }

    #[test]
    fn test_mixed_types_correct_hierarchy_order() {
        // Test that mixed types follow the exact Erlang hierarchy in encoded bytes
        let mut map_data = HashMap::new();

        // Add keys in reverse hierarchy order
        map_data.insert(Term::Binary(eetf::Binary { bytes: b"bin".to_vec() }), Term::Atom(Atom::from("last"))); // Type 9 - should be last
        map_data.insert(
            Term::List(eetf::List { elements: vec![Term::Atom(Atom::from("item"))] }),
            Term::Atom(Atom::from("eighth")),
        ); // Type 8 - should be 4th
        map_data.insert(
            Term::Tuple(eetf::Tuple { elements: vec![Term::Atom(Atom::from("item"))] }),
            Term::Atom(Atom::from("sixth")),
        ); // Type 6 - should be 3rd  
        map_data.insert(Term::Atom(Atom::from("atom")), Term::Atom(Atom::from("second"))); // Type 2 - should be 2nd
        map_data.insert(Term::FixInteger(FixInteger { value: 123 }), Term::Atom(Atom::from("first"))); // Type 1 - should be 1st

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Parse the encoded bytes to verify the key type ordering
        let mut pos = 6; // Skip ETF version + map tag + map size
        let mut actual_type_order = Vec::new();

        for _ in 0..5 {
            let key_tag = encoded[pos];
            actual_type_order.push(key_tag);

            // Skip the key based on its type
            match key_tag {
                97 => pos += 2, // small integer: tag + value
                98 => pos += 5, // integer: tag + 4-byte value
                119 => {
                    // small atom: tag + length + atom bytes
                    let len = encoded[pos + 1] as usize;
                    pos += 2 + len;
                }
                104 => {
                    // small tuple: tag + arity + elements
                    let _arity = encoded[pos + 1] as usize;
                    pos += 2; // tag + arity
                    // Skip tuple elements (we know it's one atom)
                    if encoded[pos] == 119 {
                        // small atom
                        let len = encoded[pos + 1] as usize;
                        pos += 2 + len;
                    }
                }
                108 => {
                    // list: tag + length + elements + tail
                    pos += 5; // tag + 4-byte length
                    // Skip list elements (we know it's one atom)
                    if encoded[pos] == 119 {
                        // small atom
                        let len = encoded[pos + 1] as usize;
                        pos += 2 + len;
                    }
                    pos += 1; // nil tail
                }
                109 => {
                    // binary: tag + 4-byte length + bytes
                    let len =
                        u32::from_be_bytes([encoded[pos + 1], encoded[pos + 2], encoded[pos + 3], encoded[pos + 4]])
                            as usize;
                    pos += 5 + len;
                }
                _ => panic!("Unexpected key type tag: {}", key_tag),
            }

            // Skip the value (all are atoms in this test)
            if encoded[pos] == 119 {
                // small atom
                let len = encoded[pos + 1] as usize;
                pos += 2 + len;
            }
        }

        // Expected order: Number(97), Atom(119), Tuple(104), List(108), Binary(109)
        let expected_tags = [97, 119, 104, 108, 109]; // small_int, small_atom, small_tuple, list, binary

        assert_eq!(
            actual_type_order, expected_tags,
            "Key types should follow Erlang hierarchy: Numbers, Atoms, References, Ports, PIDs, Tuples, Maps, Lists, Binaries"
        );
    }

    #[test]
    fn test_elixir_deterministic_example_simple_map() {
        // Test the exact example from DETERMINISTIC.md.local:
        // map = %{z: 1, a: 2, m: 3}
        // :erlang.term_to_binary(map, [:deterministic])
        // <<131, 116, 0, 0, 0, 3, 119, 1, 97, 97, 2, 119, 1, 109, 97, 3, 119, 1, 122, 97, 1>>

        let mut map_data = HashMap::new();
        map_data.insert(Term::Atom(Atom::from("z")), Term::FixInteger(FixInteger { value: 1 }));
        map_data.insert(Term::Atom(Atom::from("a")), Term::FixInteger(FixInteger { value: 2 }));
        map_data.insert(Term::Atom(Atom::from("m")), Term::FixInteger(FixInteger { value: 3 }));

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Expected bytes from Elixir's :erlang.term_to_binary(map, [:deterministic])
        let expected: Vec<u8> = vec![
            131, 116, 0, 0, 0, 3, // ETF version + map tag + size=3
            119, 1, 97, 97, 2, // small_atom "a" -> small_int 2
            119, 1, 109, 97, 3, // small_atom "m" -> small_int 3
            119, 1, 122, 97, 1, // small_atom "z" -> small_int 1
        ];

        assert_eq!(
            encoded, expected,
            "Our encoding should match Elixir's deterministic encoding exactly.\nOur:      {:?}\nExpected: {:?}",
            encoded, expected
        );
    }

    #[test]
    fn test_elixir_deterministic_example_mixed_types() {
        // Test the exact example from DETERMINISTIC.md.local:
        // mixed = %{:atom => 1, "string" => 2, 123 => 3}
        // :erlang.term_to_binary(mixed, [:deterministic])
        // <<131, 116, 0, 0, 0, 3, 97, 123, 97, 3, 119, 4, 97, 116, 111, 109, 97, 1, 109, 0, 0, 0, 6, 115, 116, 114, 105, 110, 103, 97, 2>>

        let mut map_data = HashMap::new();
        map_data.insert(Term::Atom(Atom::from("atom")), Term::FixInteger(FixInteger { value: 1 }));
        map_data.insert(
            Term::Binary(eetf::Binary { bytes: b"string".to_vec() }),
            Term::FixInteger(FixInteger { value: 2 }),
        );
        map_data.insert(Term::FixInteger(FixInteger { value: 123 }), Term::FixInteger(FixInteger { value: 3 }));

        let map = Term::Map(Map { map: map_data });
        let encoded = encode_safe_deterministic(&map);

        // Expected bytes from Elixir's :erlang.term_to_binary(mixed, [:deterministic])
        let expected: Vec<u8> = vec![
            131, 116, 0, 0, 0, 3, // ETF version + map tag + size=3
            97, 123, 97, 3, // small_int 123 -> small_int 3
            119, 4, 97, 116, 111, 109, 97, 1, // small_atom "atom" -> small_int 1
            109, 0, 0, 0, 6, 115, 116, 114, 105, 110, 103, 97, 2, // binary "string" -> small_int 2
        ];

        assert_eq!(
            encoded, expected,
            "Our encoding should match Elixir's deterministic encoding exactly.\nOur:      {:?}\nExpected: {:?}",
            encoded, expected
        );
    }

    #[test]
    fn test_decode_elixir_examples() {
        // Verify that the Elixir examples can be decoded correctly by the eetf library

        // Example 1: simple map
        let elixir_simple: Vec<u8> =
            vec![131, 116, 0, 0, 0, 3, 119, 1, 97, 97, 2, 119, 1, 109, 97, 3, 119, 1, 122, 97, 1];

        let decoded_simple = Term::decode(&elixir_simple[..]).unwrap();
        if let Term::Map(map) = decoded_simple {
            assert_eq!(map.map.len(), 3);
            assert_eq!(map.map.get(&Term::Atom(Atom::from("a"))), Some(&Term::FixInteger(FixInteger { value: 2 })));
            assert_eq!(map.map.get(&Term::Atom(Atom::from("m"))), Some(&Term::FixInteger(FixInteger { value: 3 })));
            assert_eq!(map.map.get(&Term::Atom(Atom::from("z"))), Some(&Term::FixInteger(FixInteger { value: 1 })));
        } else {
            panic!("Failed to decode simple map");
        }

        // Example 2: mixed types map
        let elixir_mixed: Vec<u8> = vec![
            131, 116, 0, 0, 0, 3, 97, 123, 97, 3, 119, 4, 97, 116, 111, 109, 97, 1, 109, 0, 0, 0, 6, 115, 116, 114,
            105, 110, 103, 97, 2,
        ];

        let decoded_mixed = Term::decode(&elixir_mixed[..]).unwrap();
        if let Term::Map(map) = decoded_mixed {
            assert_eq!(map.map.len(), 3);
            assert_eq!(
                map.map.get(&Term::FixInteger(FixInteger { value: 123 })),
                Some(&Term::FixInteger(FixInteger { value: 3 }))
            );
            assert_eq!(map.map.get(&Term::Atom(Atom::from("atom"))), Some(&Term::FixInteger(FixInteger { value: 1 })));
            assert_eq!(
                map.map.get(&Term::Binary(eetf::Binary { bytes: b"string".to_vec() })),
                Some(&Term::FixInteger(FixInteger { value: 2 }))
            );
        } else {
            panic!("Failed to decode mixed types map");
        }
    }

    #[test]
    fn test_comprehensive_data_cases_1_to_10() {
        // Test 1: %{m: 3, a: 1, z: 2}
        let mut map1 = HashMap::new();
        map1.insert(Term::Atom(Atom::from("m")), Term::FixInteger(FixInteger { value: 3 }));
        map1.insert(Term::Atom(Atom::from("a")), Term::FixInteger(FixInteger { value: 1 }));
        map1.insert(Term::Atom(Atom::from("z")), Term::FixInteger(FixInteger { value: 2 }));
        let term1 = Term::Map(Map { map: map1 });
        let expected1 = vec![131, 116, 0, 0, 0, 3, 119, 1, 97, 97, 1, 119, 1, 109, 97, 3, 119, 1, 122, 97, 2];
        assert_eq!(encode_safe_deterministic(&term1), expected1, "Test 1 failed");

        // Test 2: %{123 => 3, 45.67 => 4, :atom => 1, "string" => 2}
        let mut map2 = HashMap::new();
        map2.insert(Term::FixInteger(FixInteger { value: 123 }), Term::FixInteger(FixInteger { value: 3 }));
        map2.insert(Term::Float(eetf::Float { value: 45.67 }), Term::FixInteger(FixInteger { value: 4 }));
        map2.insert(Term::Atom(Atom::from("atom")), Term::FixInteger(FixInteger { value: 1 }));
        map2.insert(
            Term::Binary(eetf::Binary { bytes: b"string".to_vec() }),
            Term::FixInteger(FixInteger { value: 2 }),
        );
        let term2 = Term::Map(Map { map: map2 });
        let expected2 = vec![
            131, 116, 0, 0, 0, 4, 97, 123, 97, 3, 70, 64, 70, 213, 194, 143, 92, 40, 246, 97, 4, 119, 4, 97, 116, 111,
            109, 97, 1, 109, 0, 0, 0, 6, 115, 116, 114, 105, 110, 103, 97, 2,
        ];
        assert_eq!(encode_safe_deterministic(&term2), expected2, "Test 2 failed");

        // Test 3: %{outer: %{inner: %{deep: :value}}, top: :level}
        let mut inner_inner = HashMap::new();
        inner_inner.insert(Term::Atom(Atom::from("deep")), Term::Atom(Atom::from("value")));
        let mut inner = HashMap::new();
        inner.insert(Term::Atom(Atom::from("inner")), Term::Map(Map { map: inner_inner }));
        let mut map3 = HashMap::new();
        map3.insert(Term::Atom(Atom::from("outer")), Term::Map(Map { map: inner }));
        map3.insert(Term::Atom(Atom::from("top")), Term::Atom(Atom::from("level")));
        let term3 = Term::Map(Map { map: map3 });
        let expected3 = vec![
            131, 116, 0, 0, 0, 2, 119, 5, 111, 117, 116, 101, 114, 116, 0, 0, 0, 1, 119, 5, 105, 110, 110, 101, 114,
            116, 0, 0, 0, 1, 119, 4, 100, 101, 101, 112, 119, 5, 118, 97, 108, 117, 101, 119, 3, 116, 111, 112, 119, 5,
            108, 101, 118, 101, 108,
        ];
        assert_eq!(encode_safe_deterministic(&term3), expected3, "Test 3 failed");

        // Test 4: [1, :atom, "string", [nested: :list], %{map: :inside}]
        let nested_map = {
            let mut m = HashMap::new();
            m.insert(Term::Atom(Atom::from("map")), Term::Atom(Atom::from("inside")));
            Term::Map(Map { map: m })
        };
        let term4 = Term::List(eetf::List {
            elements: vec![
                Term::FixInteger(FixInteger { value: 1 }),
                Term::Atom(Atom::from("atom")),
                Term::Binary(eetf::Binary { bytes: b"string".to_vec() }),
                Term::List(eetf::List {
                    elements: vec![Term::Tuple(eetf::Tuple {
                        elements: vec![Term::Atom(Atom::from("nested")), Term::Atom(Atom::from("list"))],
                    })],
                }),
                nested_map,
            ],
        });
        let expected4 = vec![
            131, 108, 0, 0, 0, 5, 97, 1, 119, 4, 97, 116, 111, 109, 109, 0, 0, 0, 6, 115, 116, 114, 105, 110, 103, 108,
            0, 0, 0, 1, 104, 2, 119, 6, 110, 101, 115, 116, 101, 100, 119, 4, 108, 105, 115, 116, 106, 116, 0, 0, 0, 1,
            119, 3, 109, 97, 112, 119, 6, 105, 110, 115, 105, 100, 101, 106,
        ];
        assert_eq!(encode_safe_deterministic(&term4), expected4, "Test 4 failed");

        // Test 5: {:simple, :tuple, 123, "mixed"}
        let term5 = Term::Tuple(eetf::Tuple {
            elements: vec![
                Term::Atom(Atom::from("simple")),
                Term::Atom(Atom::from("tuple")),
                Term::FixInteger(FixInteger { value: 123 }),
                Term::Binary(eetf::Binary { bytes: b"mixed".to_vec() }),
            ],
        });
        let expected5 = vec![
            131, 104, 4, 119, 6, 115, 105, 109, 112, 108, 101, 119, 5, 116, 117, 112, 108, 101, 97, 123, 109, 0, 0, 0,
            5, 109, 105, 120, 101, 100,
        ];
        assert_eq!(encode_safe_deterministic(&term5), expected5, "Test 5 failed");

        // Test 6: %{"apple" => :a, "monkey" => :m, "zebra" => :z}
        let mut map6 = HashMap::new();
        map6.insert(Term::Binary(eetf::Binary { bytes: b"apple".to_vec() }), Term::Atom(Atom::from("a")));
        map6.insert(Term::Binary(eetf::Binary { bytes: b"monkey".to_vec() }), Term::Atom(Atom::from("m")));
        map6.insert(Term::Binary(eetf::Binary { bytes: b"zebra".to_vec() }), Term::Atom(Atom::from("z")));
        let term6 = Term::Map(Map { map: map6 });
        let expected6 = vec![
            131, 116, 0, 0, 0, 3, 109, 0, 0, 0, 5, 97, 112, 112, 108, 101, 119, 1, 97, 109, 0, 0, 0, 6, 109, 111, 110,
            107, 101, 121, 119, 1, 109, 109, 0, 0, 0, 5, 122, 101, 98, 114, 97, 119, 1, 122,
        ];
        assert_eq!(encode_safe_deterministic(&term6), expected6, "Test 6 failed");

        // Test 7: %{-5 => :negative, 1 => :one, 999 => :big, 2.5 => :two_half}
        let mut map7 = HashMap::new();
        map7.insert(Term::FixInteger(FixInteger { value: -5 }), Term::Atom(Atom::from("negative")));
        map7.insert(Term::FixInteger(FixInteger { value: 1 }), Term::Atom(Atom::from("one")));
        map7.insert(Term::FixInteger(FixInteger { value: 999 }), Term::Atom(Atom::from("big")));
        map7.insert(Term::Float(eetf::Float { value: 2.5 }), Term::Atom(Atom::from("two_half")));
        let term7 = Term::Map(Map { map: map7 });
        let expected7 = vec![
            131, 116, 0, 0, 0, 4, 98, 255, 255, 255, 251, 119, 8, 110, 101, 103, 97, 116, 105, 118, 101, 97, 1, 119, 3,
            111, 110, 101, 98, 0, 0, 3, 231, 119, 3, 98, 105, 103, 70, 64, 4, 0, 0, 0, 0, 0, 0, 119, 8, 116, 119, 111,
            95, 104, 97, 108, 102,
        ];
        assert_eq!(encode_safe_deterministic(&term7), expected7, "Test 7 failed");

        // Test 8: Complex nested structure (simplified)
        let mut config_map = HashMap::new();
        config_map.insert(Term::Atom(Atom::from("debug")), Term::Atom(Atom::from("true")));
        config_map.insert(Term::Atom(Atom::from("timeout")), Term::FixInteger(FixInteger { value: 5000 }));

        let mut user1 = HashMap::new();
        user1.insert(Term::Atom(Atom::from("id")), Term::FixInteger(FixInteger { value: 1 }));
        user1.insert(Term::Atom(Atom::from("name")), Term::Binary(eetf::Binary { bytes: b"Alice".to_vec() }));
        user1.insert(
            Term::Atom(Atom::from("roles")),
            Term::List(eetf::List { elements: vec![Term::Atom(Atom::from("admin")), Term::Atom(Atom::from("user"))] }),
        );

        let mut user2 = HashMap::new();
        user2.insert(Term::Atom(Atom::from("id")), Term::FixInteger(FixInteger { value: 2 }));
        user2.insert(Term::Atom(Atom::from("name")), Term::Binary(eetf::Binary { bytes: b"Bob".to_vec() }));
        user2.insert(
            Term::Atom(Atom::from("roles")),
            Term::List(eetf::List { elements: vec![Term::Atom(Atom::from("user"))] }),
        );

        let mut map8 = HashMap::new();
        map8.insert(Term::Atom(Atom::from("config")), Term::Map(Map { map: config_map }));
        map8.insert(
            Term::Atom(Atom::from("users")),
            Term::List(eetf::List { elements: vec![Term::Map(Map { map: user1 }), Term::Map(Map { map: user2 })] }),
        );
        let term8 = Term::Map(Map { map: map8 });
        let expected8 = vec![
            131, 116, 0, 0, 0, 2, 119, 6, 99, 111, 110, 102, 105, 103, 116, 0, 0, 0, 2, 119, 5, 100, 101, 98, 117, 103,
            119, 4, 116, 114, 117, 101, 119, 7, 116, 105, 109, 101, 111, 117, 116, 98, 0, 0, 19, 136, 119, 5, 117, 115,
            101, 114, 115, 108, 0, 0, 0, 2, 116, 0, 0, 0, 3, 119, 2, 105, 100, 97, 1, 119, 4, 110, 97, 109, 101, 109,
            0, 0, 0, 5, 65, 108, 105, 99, 101, 119, 5, 114, 111, 108, 101, 115, 108, 0, 0, 0, 2, 119, 5, 97, 100, 109,
            105, 110, 119, 4, 117, 115, 101, 114, 106, 116, 0, 0, 0, 3, 119, 2, 105, 100, 97, 2, 119, 4, 110, 97, 109,
            101, 109, 0, 0, 0, 3, 66, 111, 98, 119, 5, 114, 111, 108, 101, 115, 108, 0, 0, 0, 1, 119, 4, 117, 115, 101,
            114, 106, 106,
        ];
        assert_eq!(encode_safe_deterministic(&term8), expected8, "Test 8 failed");

        // Test 9: %{1 => %{"nested" => %{deep: %{4 => :very_deep}}}, :top => "level"}
        let mut deepest = HashMap::new();
        deepest.insert(Term::FixInteger(FixInteger { value: 4 }), Term::Atom(Atom::from("very_deep")));
        let mut deep_map = HashMap::new();
        deep_map.insert(Term::Atom(Atom::from("deep")), Term::Map(Map { map: deepest }));
        let mut nested_map = HashMap::new();
        nested_map.insert(Term::Binary(eetf::Binary { bytes: b"nested".to_vec() }), Term::Map(Map { map: deep_map }));
        let mut map9 = HashMap::new();
        map9.insert(Term::FixInteger(FixInteger { value: 1 }), Term::Map(Map { map: nested_map }));
        map9.insert(Term::Atom(Atom::from("top")), Term::Binary(eetf::Binary { bytes: b"level".to_vec() }));
        let term9 = Term::Map(Map { map: map9 });
        let expected9 = vec![
            131, 116, 0, 0, 0, 2, 97, 1, 116, 0, 0, 0, 1, 109, 0, 0, 0, 6, 110, 101, 115, 116, 101, 100, 116, 0, 0, 0,
            1, 119, 4, 100, 101, 101, 112, 116, 0, 0, 0, 1, 97, 4, 119, 9, 118, 101, 114, 121, 95, 100, 101, 101, 112,
            119, 3, 116, 111, 112, 109, 0, 0, 0, 5, 108, 101, 118, 101, 108,
        ];
        assert_eq!(encode_safe_deterministic(&term9), expected9, "Test 9 failed");

        // Test 10: [{:name, "John"}, {:age, 30}, {:city, "NYC"}, {1, :number_key}]
        let term10 = Term::List(eetf::List {
            elements: vec![
                Term::Tuple(eetf::Tuple {
                    elements: vec![
                        Term::Atom(Atom::from("name")),
                        Term::Binary(eetf::Binary { bytes: b"John".to_vec() }),
                    ],
                }),
                Term::Tuple(eetf::Tuple {
                    elements: vec![Term::Atom(Atom::from("age")), Term::FixInteger(FixInteger { value: 30 })],
                }),
                Term::Tuple(eetf::Tuple {
                    elements: vec![
                        Term::Atom(Atom::from("city")),
                        Term::Binary(eetf::Binary { bytes: b"NYC".to_vec() }),
                    ],
                }),
                Term::Tuple(eetf::Tuple {
                    elements: vec![Term::FixInteger(FixInteger { value: 1 }), Term::Atom(Atom::from("number_key"))],
                }),
            ],
        });
        let expected10 = vec![
            131, 108, 0, 0, 0, 4, 104, 2, 119, 4, 110, 97, 109, 101, 109, 0, 0, 0, 4, 74, 111, 104, 110, 104, 2, 119,
            3, 97, 103, 101, 97, 30, 104, 2, 119, 4, 99, 105, 116, 121, 109, 0, 0, 0, 3, 78, 89, 67, 104, 2, 97, 1,
            119, 10, 110, 117, 109, 98, 101, 114, 95, 107, 101, 121, 106,
        ];
        assert_eq!(encode_safe_deterministic(&term10), expected10, "Test 10 failed");
    }

    #[test]
    fn test_comprehensive_data_cases_special_selection() {
        // Test 23: ANR-like structure - critical for this project
        let mut map23 = HashMap::new();
        map23.insert(Term::Atom(Atom::from("port")), Term::FixInteger(FixInteger { value: 36969 }));
        map23.insert(Term::Atom(Atom::from("version")), Term::Binary(eetf::Binary { bytes: b"1.1.5".to_vec() }));
        map23.insert(Term::Atom(Atom::from("signature")), Term::Binary(eetf::Binary { bytes: vec![13, 14, 15, 16] }));
        map23.insert(Term::Atom(Atom::from("pop")), Term::Binary(eetf::Binary { bytes: vec![9, 10, 11, 12] }));
        map23.insert(Term::Atom(Atom::from("ip4")), Term::Binary(eetf::Binary { bytes: b"192.168.1.1".to_vec() }));
        map23.insert(Term::Atom(Atom::from("ts")), Term::FixInteger(FixInteger { value: 1640995200 }));
        map23.insert(Term::Atom(Atom::from("pk")), Term::Binary(eetf::Binary { bytes: vec![1, 2, 3, 4, 5, 6, 7, 8] }));
        map23.insert(Term::Atom(Atom::from("anr_name")), Term::Binary(eetf::Binary { bytes: b"test_node".to_vec() }));
        map23.insert(
            Term::Atom(Atom::from("anr_desc")),
            Term::Binary(eetf::Binary { bytes: b"Test description".to_vec() }),
        );
        let term23 = Term::Map(Map { map: map23 });
        let expected23 = vec![
            131, 116, 0, 0, 0, 9, 119, 8, 97, 110, 114, 95, 100, 101, 115, 99, 109, 0, 0, 0, 16, 84, 101, 115, 116, 32,
            100, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 119, 8, 97, 110, 114, 95, 110, 97, 109, 101, 109, 0,
            0, 0, 9, 116, 101, 115, 116, 95, 110, 111, 100, 101, 119, 3, 105, 112, 52, 109, 0, 0, 0, 11, 49, 57, 50,
            46, 49, 54, 56, 46, 49, 46, 49, 119, 2, 112, 107, 109, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 119, 3, 112,
            111, 112, 109, 0, 0, 0, 4, 9, 10, 11, 12, 119, 4, 112, 111, 114, 116, 98, 0, 0, 144, 105, 119, 9, 115, 105,
            103, 110, 97, 116, 117, 114, 101, 109, 0, 0, 0, 4, 13, 14, 15, 16, 119, 2, 116, 115, 98, 97, 207, 153, 128,
            119, 7, 118, 101, 114, 115, 105, 111, 110, 109, 0, 0, 0, 5, 49, 46, 49, 46, 53,
        ];
        assert_eq!(encode_safe_deterministic(&term23), expected23, "Test 23 (ANR) failed");

        // Test 11: Maps with tuple keys
        let mut map11 = HashMap::new();
        map11.insert(Term::Atom(Atom::from("simple")), Term::Atom(Atom::from("value3")));
        map11.insert(
            Term::Tuple(eetf::Tuple {
                elements: vec![Term::Atom(Atom::from("another")), Term::Atom(Atom::from("compound"))],
            }),
            Term::Atom(Atom::from("value2")),
        );
        map11.insert(
            Term::Tuple(eetf::Tuple {
                elements: vec![Term::Atom(Atom::from("compound")), Term::Atom(Atom::from("key"))],
            }),
            Term::Atom(Atom::from("value1")),
        );
        let term11 = Term::Map(Map { map: map11 });
        let expected11 = vec![
            131, 116, 0, 0, 0, 3, 119, 6, 115, 105, 109, 112, 108, 101, 119, 6, 118, 97, 108, 117, 101, 51, 104, 2,
            119, 7, 97, 110, 111, 116, 104, 101, 114, 119, 8, 99, 111, 109, 112, 111, 117, 110, 100, 119, 6, 118, 97,
            108, 117, 101, 50, 104, 2, 119, 8, 99, 111, 109, 112, 111, 117, 110, 100, 119, 3, 107, 101, 121, 119, 6,
            118, 97, 108, 117, 101, 49,
        ];
        assert_eq!(encode_safe_deterministic(&term11), expected11, "Test 11 failed");

        // Test 13: Simple list - order shouldn't change (lists aren't sorted internally)
        let term13 = Term::List(eetf::List {
            elements: vec![
                Term::Atom(Atom::from("zebra")),
                Term::Atom(Atom::from("alpha")),
                Term::Atom(Atom::from("beta")),
                Term::Atom(Atom::from("gamma")),
                Term::Atom(Atom::from("omega")),
            ],
        });
        let expected13 = vec![
            131, 108, 0, 0, 0, 5, 119, 5, 122, 101, 98, 114, 97, 119, 5, 97, 108, 112, 104, 97, 119, 4, 98, 101, 116,
            97, 119, 5, 103, 97, 109, 109, 97, 119, 5, 111, 109, 101, 103, 97, 106,
        ];
        assert_eq!(encode_safe_deterministic(&term13), expected13, "Test 13 failed");

        // Test 21: Number ordering verification
        let mut map21 = HashMap::new();
        map21.insert(Term::FixInteger(FixInteger { value: 1 }), Term::Atom(Atom::from("one")));
        map21.insert(Term::FixInteger(FixInteger { value: 500 }), Term::Atom(Atom::from("five_hundred")));
        map21.insert(Term::FixInteger(FixInteger { value: 99999 }), Term::Atom(Atom::from("almost_hundred_k")));
        map21.insert(Term::FixInteger(FixInteger { value: 1000000 }), Term::Atom(Atom::from("million")));
        let term21 = Term::Map(Map { map: map21 });
        let expected21 = vec![
            131, 116, 0, 0, 0, 4, 97, 1, 119, 3, 111, 110, 101, 98, 0, 0, 1, 244, 119, 12, 102, 105, 118, 101, 95, 104,
            117, 110, 100, 114, 101, 100, 98, 0, 1, 134, 159, 119, 16, 97, 108, 109, 111, 115, 116, 95, 104, 117, 110,
            100, 114, 101, 100, 95, 107, 98, 0, 15, 66, 64, 119, 7, 109, 105, 108, 108, 105, 111, 110,
        ];
        assert_eq!(encode_safe_deterministic(&term21), expected21, "Test 21 failed");

        // Test 29: Negative numbers and zero ordering
        let mut map29 = HashMap::new();
        map29.insert(Term::FixInteger(FixInteger { value: -1000 }), Term::Atom(Atom::from("neg_thousand")));
        map29.insert(Term::FixInteger(FixInteger { value: -1 }), Term::Atom(Atom::from("neg_one")));
        map29.insert(Term::FixInteger(FixInteger { value: 0 }), Term::Atom(Atom::from("zero")));
        map29.insert(Term::Float(eetf::Float { value: 0.0 }), Term::Atom(Atom::from("float_zero")));
        let term29 = Term::Map(Map { map: map29 });
        let expected29 = vec![
            131, 116, 0, 0, 0, 4, 98, 255, 255, 252, 24, 119, 12, 110, 101, 103, 95, 116, 104, 111, 117, 115, 97, 110,
            100, 98, 255, 255, 255, 255, 119, 7, 110, 101, 103, 95, 111, 110, 101, 97, 0, 119, 4, 122, 101, 114, 111,
            70, 0, 0, 0, 0, 0, 0, 0, 0, 119, 10, 102, 108, 111, 97, 116, 95, 122, 101, 114, 111,
        ];
        assert_eq!(encode_safe_deterministic(&term29), expected29, "Test 29 failed");
    }

    #[test]
    fn test_comprehensive_data_byte_list_cases() {
        // Test 14: Mixed data types in map
        let mut map14 = HashMap::new();
        map14.insert(Term::Atom(Atom::from("binary")), Term::Binary(eetf::Binary { bytes: vec![1, 2, 3] }));
        map14.insert(Term::Atom(Atom::from("list")), Term::ByteList(eetf::ByteList { bytes: vec![1, 2, 3] }));
        map14.insert(Term::Atom(Atom::from("map")), {
            let mut inner = HashMap::new();
            inner.insert(Term::Atom(Atom::from("a")), Term::FixInteger(FixInteger { value: 1 }));
            inner.insert(Term::Atom(Atom::from("b")), Term::FixInteger(FixInteger { value: 2 }));
            Term::Map(Map { map: inner })
        });
        map14.insert(
            Term::Atom(Atom::from("tuple")),
            Term::Tuple(eetf::Tuple {
                elements: vec![
                    Term::FixInteger(FixInteger { value: 1 }),
                    Term::FixInteger(FixInteger { value: 2 }),
                    Term::FixInteger(FixInteger { value: 3 }),
                ],
            }),
        );
        let term14 = Term::Map(Map { map: map14 });
        let expected14 = vec![
            131, 116, 0, 0, 0, 4, 119, 6, 98, 105, 110, 97, 114, 121, 109, 0, 0, 0, 3, 1, 2, 3, 119, 4, 108, 105, 115,
            116, 107, 0, 3, 1, 2, 3, 119, 3, 109, 97, 112, 116, 0, 0, 0, 2, 119, 1, 97, 97, 1, 119, 1, 98, 97, 2, 119,
            5, 116, 117, 112, 108, 101, 104, 3, 97, 1, 97, 2, 97, 3,
        ];
        assert_eq!(encode_safe_deterministic(&term14), expected14, "Test 14 failed");

        // Test 34: Charlists and strings
        let mut map34 = HashMap::new();
        map34.insert(Term::Atom(Atom::from("string")), Term::Binary(eetf::Binary { bytes: b"hello".to_vec() }));
        map34.insert(Term::Atom(Atom::from("charlist")), Term::ByteList(eetf::ByteList { bytes: b"hello".to_vec() }));
        map34.insert(Term::Atom(Atom::from("mixed_list")), Term::ByteList(eetf::ByteList { bytes: b"Hello".to_vec() }));
        let term34 = Term::Map(Map { map: map34 });
        let expected34 = vec![
            131, 116, 0, 0, 0, 3, 119, 8, 99, 104, 97, 114, 108, 105, 115, 116, 107, 0, 5, 104, 101, 108, 108, 111,
            119, 10, 109, 105, 120, 101, 100, 95, 108, 105, 115, 116, 107, 0, 5, 72, 101, 108, 108, 111, 119, 6, 115,
            116, 114, 105, 110, 103, 109, 0, 0, 0, 5, 104, 101, 108, 108, 111,
        ];
        assert_eq!(encode_safe_deterministic(&term34), expected34, "Test 34 failed");
    }
}
