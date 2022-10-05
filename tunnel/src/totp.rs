/// A simple TOTP implementation, intended to be used by reply filter
use std::time::SystemTime;

use crate::utils::possibly_insecure_hash_with_key;

const CONTEXT: &[u8] = b"TOTP for the secure tunnel under snow";

#[derive(Debug, Clone)]
pub struct Totp {
    key: [u8; 32],
    step: u64,
    skew: u8,
}

impl Totp {
    pub fn new(key: impl AsRef<[u8]>, step_in_secs: u64, skew: u8) -> Self {
        Totp {
            key: possibly_insecure_hash_with_key(CONTEXT, key),
            step: step_in_secs,
            skew,
        }
    }

    pub fn generate<const N: usize>(&self, time: u64) -> [u8; N] {
        <[u8; N]>::try_from(
            &possibly_insecure_hash_with_key(self.key, (time / self.step).to_be_bytes())[..N],
        )
        .unwrap()
    }

    #[inline(always)]
    pub fn generate_current<const N: usize>(&self) -> [u8; N] {
        self.generate(system_now())
    }

    #[inline(always)]
    pub fn sign<const N: usize>(&self, time: u64, nonce: impl AsRef<[u8]>) -> [u8; N] {
        <[u8; N]>::try_from(&possibly_insecure_hash_with_key(self.generate::<N>(time), nonce)[..N])
            .unwrap()
    }

    #[inline(always)]
    pub fn sign_current<const N: usize>(&self, nonce: impl AsRef<[u8]>) -> [u8; N] {
        self.sign(system_now(), nonce)
    }

    #[inline(always)]
    pub fn check<const N: usize>(&self, token: &[u8; N], time: u64) -> bool {
        self.check_with(|t| t == token, time)
    }

    pub fn check_with<const N: usize>(&self, f: impl Fn(&[u8; N]) -> bool, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..=self.skew * 2 {
            let step_time = (basestep + (i as u64)) * (self.step as u64);
            if f(&self.generate(step_time)) {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    pub fn check_current<const N: usize>(&self, token: &[u8; N]) -> bool {
        self.check(token, system_now())
    }

    #[inline(always)]
    pub fn check_current_with<const N: usize>(&self, f: impl Fn(&[u8; N]) -> bool) -> bool {
        self.check_with(f, system_now())
    }

    pub fn verify<const N: usize>(
        &self,
        nonce: impl AsRef<[u8]>,
        sig: &[u8; N],
        time: u64,
    ) -> bool {
        let nonce = nonce.as_ref();
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..=self.skew * 2 {
            let step_time = (basestep + (i as u64)) * (self.step as u64);
            if &self.sign(step_time, nonce) == sig {
                return true;
            }
        }
        false
    }
    #[inline(always)]
    pub fn verify_current<const N: usize>(&self, nonce: impl AsRef<[u8]>, sig: &[u8; N]) -> bool {
        self.verify(nonce, sig, system_now())
    }
}

#[inline(always)]
fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Now is after UNIX epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::Totp;

    #[test]
    fn generate_and_check() {
        let totp = Totp::new("pamyu", 60, 2);
        assert!(totp.check_current(&totp.generate_current::<32>()));
        assert!(!totp.check_current(&totp.generate::<32>(0)));
    }

    #[test]
    fn sign_and_verify() {
        let totp = Totp::new("pamyu", 60, 2);
        let nonce = "00010";
        assert!(totp.verify_current(nonce, &totp.sign_current::<32>(nonce)));
    }
}
