pub mod coin;
pub mod coin_symbol_reserved;
pub mod epoch;
pub mod protocol;
pub mod sol;
pub mod sol_bloom;
pub mod sol_difficulty;

pub fn eetf_list_of_binaries(list_of_binaries: Vec<Vec<u8>>) -> Result<Vec<u8>, eetf::EncodeError> {
    let elements: Vec<eetf::Term> = list_of_binaries
        .into_iter()
        .map(|bytes| eetf::Term::from(eetf::Binary { bytes }))
        .collect();

    let term = eetf::Term::from(eetf::List::from(elements));
    let mut out = Vec::new();
    term.encode(&mut out)?;
    Ok(out)
}
