use std::any::type_name_of_val;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Guard that creates a per-test directory under /tmp and deletes it on drop.
pub struct TmpTestDir {
    path: PathBuf,
}

impl TmpTestDir {
    /// Create a tmp directory named "/tmp/<fully-qualified-test-path><seconds-since-epoch>".
    /// Pass a reference to the test function item, e.g., `TmpTestDir::for_test(&my_test_fn)`.
    pub fn for_test<F: ?Sized>(f: &F) -> std::io::Result<Self> {
        let fq = type_name_of_val(f);
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let dir_name = format!("{}{}", fq, secs);
        let path = Path::new("/tmp").join(dir_name);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }


    /// Convenience to get &str path.
    pub fn to_str(&self) -> &str {
        self.path.to_str().unwrap_or("")
    }
}

impl Drop for TmpTestDir {
    fn drop(&mut self) {
        // best-effort cleanup
        let _ = fs::remove_dir_all(&self.path);
    }
}
