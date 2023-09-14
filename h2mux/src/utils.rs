use std::io;

pub fn h2_to_io_error(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        io::Error::new(io::ErrorKind::Other, e)
    }
}
