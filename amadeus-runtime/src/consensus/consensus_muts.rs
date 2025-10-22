#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    Put { op: Vec<u8>, key: Vec<u8>, value: Vec<u8> },
    Delete { op: Vec<u8>, key: Vec<u8> },
    SetBit { op: Vec<u8>, key: Vec<u8>, value: u64, bloomsize: u64 },
    ClearBit { op: Vec<u8>, key: Vec<u8>, value: u64 },
}
