use tokio::io;

use std::fmt::Display;

#[derive(Debug)]
pub struct CopyBidiError {
    pub source: CopyBidiErrorSource,
    pub error: io::Error,
}

#[derive(Debug)]
pub enum CopyBidiErrorSource {
    ReadA,
    WriteB,
    ReadB,
    WriteA,
}

pub(crate) struct CopyError {
    source: CopyErrorSource,
    error: io::Error,
}

pub(crate) enum CopyErrorSource {
    Read,
    Write,
}

impl Display for CopyBidiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.source, self.error)
    }
}

impl Into<io::Error> for CopyBidiError {
    fn into(self) -> io::Error {
        io::Error::new(io::ErrorKind::Other, self.to_string())
    }
}

impl CopyBidiError {
    fn read_a(error: io::Error) -> Self {
        Self {
            source: CopyBidiErrorSource::ReadA,
            error,
        }
    }

    fn write_b(error: io::Error) -> Self {
        Self {
            source: CopyBidiErrorSource::WriteB,
            error,
        }
    }

    fn read_b(error: io::Error) -> Self {
        Self {
            source: CopyBidiErrorSource::ReadB,
            error,
        }
    }

    fn write_a(error: io::Error) -> Self {
        Self {
            source: CopyBidiErrorSource::WriteA,
            error,
        }
    }

    pub(crate) fn a_to_b(error: CopyError) -> Self {
        match error.source {
            CopyErrorSource::Read => Self::read_a(error.error),
            CopyErrorSource::Write => Self::write_a(error.error),
        }
    }

    pub(crate) fn b_to_a(error: CopyError) -> Self {
        match error.source {
            CopyErrorSource::Read => Self::read_b(error.error),
            CopyErrorSource::Write => Self::write_b(error.error),
        }
    }
}

impl CopyError {
    pub(crate) fn read(error: io::Error) -> Self {
        Self {
            source: CopyErrorSource::Read,
            error,
        }
    }

    pub(crate) fn write(error: io::Error) -> Self {
        Self {
            source: CopyErrorSource::Write,
            error,
        }
    }
}

impl Into<io::Error> for CopyError {
    fn into(self) -> io::Error {
        self.error
    }
}

// pub(crate) trait CopyIoErrorExt {
//   fn read(self) -> CopyError;
//   fn write(self) -> CopyError;
// }

// impl CopyIoErrorExt for io::Error {
//   fn read(self) -> CopyError {
//     CopyError::read(self)
//   }

//   fn write(self) -> CopyError {
//     CopyError::write(self)
//   }
// }
