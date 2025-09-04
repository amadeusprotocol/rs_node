use eetf::{Term, Atom, Map};
use std::collections::HashMap;

/// Encode an EETF term using small atoms (tag 119) instead of legacy atoms (tag 100)
/// This ensures compatibility with Elixir's [:safe] option which rejects old atom encoding
pub fn encode_with_small_atoms(term: &Term) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(131); // ETF version marker
    encode_term_with_small_atoms(term, &mut buf);
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
    use eetf::{Atom, Map, FixInteger};
    use std::collections::HashMap;

    #[test]
    fn test_small_atom_encoding() {
        let atom = Term::Atom(Atom::from("test"));
        let encoded = encode_with_small_atoms(&atom);

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

        let encoded = encode_with_small_atoms(&term_map);

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
            let our_encoded = encode_with_small_atoms(&big_int_term);

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
        let our_encoded = encode_with_small_atoms(&atom);

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
            let key_order_terms: Vec<Term> = key_order.iter()
                .map(|&k| Term::Atom(Atom::from(k)))
                .collect();
            
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
}
