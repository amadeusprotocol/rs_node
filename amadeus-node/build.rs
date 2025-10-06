fn main() {
    println!("cargo:rustc-env=CRATE_VERSION={}", env!("CARGO_PKG_VERSION"));
}
