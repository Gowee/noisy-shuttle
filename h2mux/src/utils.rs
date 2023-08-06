use std::io;

use h2;

pub trait H2MapIoErr<T> {
    fn map_io_err(self) -> Result<T, io::Error>;
}

impl<T> H2MapIoErr<T> for Result<T, h2::Error> {
    fn map_io_err(self) -> Result<T, io::Error> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => {
                if err.is_io() {
                    Err(err.into_io().unwrap())
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
                }
            }
        }
    }
}
