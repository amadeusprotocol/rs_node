/// Compression utilities to match Elixir reference implementation
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use std::io::{Read, Write};

/// Compress data using raw deflate compression (compatible with Elixir's deflate_compress)
pub fn compress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data)?;
    encoder.finish()
}

/// Decompress data using raw deflate decompression (compatible with Elixir's deflate_decompress)
pub fn decompress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)?;
    Ok(result)
}