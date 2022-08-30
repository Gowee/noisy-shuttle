use rustls;

use std::convert::TryFrom;

pub fn u16_from_slice(s: &[u8]) -> u16 {
    u16::from_be_bytes(<[u8; 2]>::try_from(s).unwrap())
}

pub struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

// fn disable_certificate_verification(cfg: &mut rustls::ClientConfig) {
//     cfg.dangerous()
//         .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
// }
