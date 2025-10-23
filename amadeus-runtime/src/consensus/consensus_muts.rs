#[derive(Clone, Debug)]
pub enum Mutation {
    Put { op: Vec<u8>, key: Vec<u8>, value: Vec<u8> },
    Delete { op: Vec<u8>, key: Vec<u8> },
    SetBit { op: Vec<u8>, key: Vec<u8>, value: u64, bloomsize: u64 },
    ClearBit { op: Vec<u8>, key: Vec<u8>, value: u64 },
}

use std::collections::HashMap;

#[inline]
fn u64_ascii(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

pub fn mutations_to_map(muts: Vec<Mutation>) -> Vec<HashMap<Vec<u8>, Vec<u8>>> {
    let mut out = Vec::with_capacity(muts.len());

    for m in muts {
        let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(5);

        match m {
            Mutation::Put { op, key, value } => {
                map.insert(b"op".to_vec(), op); // move
                map.insert(b"key".to_vec(), key); // move
                map.insert(b"value".to_vec(), value); // move
            }
            Mutation::Delete { op, key } => {
                map.insert(b"op".to_vec(), op);
                map.insert(b"key".to_vec(), key);
            }
            Mutation::SetBit { op, key, value, bloomsize } => {
                map.insert(b"op".to_vec(), op);
                map.insert(b"key".to_vec(), key);
                map.insert(b"value".to_vec(), u64_ascii(value));
                map.insert(b"bloomsize".to_vec(), u64_ascii(bloomsize));
            }
            Mutation::ClearBit { op, key, value } => {
                map.insert(b"op".to_vec(), op);
                map.insert(b"key".to_vec(), key);
                map.insert(b"value".to_vec(), u64_ascii(value));
            }
        }

        out.push(map);
    }

    out
}
