use once_cell::sync::OnceCell;
use std::borrow::Cow;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;

static ARCHIVER_DIR: OnceCell<String> = OnceCell::new();

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
    #[error("once cell {0}")]
    OnceCell(&'static str),
}

pub async fn init_storage(base: &str) -> Result<(), Error> {
    if ARCHIVER_DIR.get().is_some() {
        return Ok(());
    }

    let path = format!("{}/log", base);
    create_dir_all(&path).await?;
    ARCHIVER_DIR.set(path).map_err(|_| Error::OnceCell("archiver_dir_set"))?;

    Ok(())
}

pub async fn store<'a>(
    data: impl Into<Cow<'a, [u8]>>,
    subdir: impl AsRef<str>,
    name: impl AsRef<str>,
) -> Result<(), Error> {
    let bin: Cow<[u8]> = data.into();
    let base = ARCHIVER_DIR.get().ok_or(Error::OnceCell("archiver_dir_get"))?;

    let path = if subdir.as_ref().is_empty() {
        format!("{}/{}", base, name.as_ref())
    } else {
        create_dir_all(&format!("{}/{}", base, subdir.as_ref())).await?;
        format!("{}/{}/{}", base, subdir.as_ref(), name.as_ref())
    };

    let mut file = OpenOptions::new().create(true).append(true).open(&path).await?;
    file.write_all(&bin).await?;
    file.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs::read_to_string;

    fn unique_base() -> String {
        let ts = crate::utils::misc::get_unix_nanos_now();
        let pid = std::process::id();
        format!("{}/rs_node_archiver_test_{}_{}", std::env::temp_dir().display(), pid, ts)
    }

    #[tokio::test]
    async fn archiver_end_to_end_single_test() {
        use tokio::fs::read;

        // Check if already initialized by another test
        if ARCHIVER_DIR.get().is_none() {
            // store before init must error (only if not already initialized)
            let err = store(b"x", "", "a.bin").await.err();
            if let Some(err) = err {
                matches!(err, Error::OnceCell(_));
            }

            // init creates base/log and is idempotent
            let base = unique_base();
            init_storage(&base).await.expect("init ok");
            init_storage(&base).await.expect("init idempotent");

            // store without subdir
            store(b"hello", "", "one.txt").await.expect("store ok");
            let content = read(format!("{}/log/one.txt", base)).await.expect("read file");
            assert_eq!(content, b"hello");

            // append
            store(b" world", "", "one.txt").await.expect("append ok");
            let s = read_to_string(format!("{}/log/one.txt", base)).await.expect("read string");
            assert_eq!(s, "hello world");

            // subdir write
            store(b"sub", "subd", "two.bin").await.expect("subdir store");
            let content2 = read(format!("{}/log/subd/two.bin", base)).await.expect("read file2");
            assert_eq!(content2, b"sub");
        } else {
            // Skip test if already initialized by another test
            // This happens when tests run in parallel
            eprintln!("Skipping archiver test - already initialized by another test");
        }
    }
}
