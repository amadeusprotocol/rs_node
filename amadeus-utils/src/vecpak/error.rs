use serde::{de, ser};
use std::fmt::{self, Display};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Message(String),
    Eof,
    TrailingBytes,
    InvalidTag,
    InvalidLength,
    InvalidUtf8,
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::Eof => write!(f, "unexpected end of input"),
            Error::TrailingBytes => write!(f, "trailing bytes after value"),
            Error::InvalidTag => write!(f, "invalid type tag"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8"),
        }
    }
}

impl std::error::Error for Error {}
