/// A simple TOTP implementation, intended to be used by reply filter
use std::time::SystemTime;

use crate::utils::hmac;

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
            key: hmac(CONTEXT, key),
            step: step_in_secs,
            skew,
        }
    }

    pub fn generate<const N: usize>(&self, time: u64) -> [u8; N] {
        <[u8; N]>::try_from(&hmac(self.key, (time / self.step).to_be_bytes())[..N]).unwrap()
    }

    #[inline(always)]
    pub fn generate_current<const N: usize>(&self) -> [u8; N] {
        self.generate(system_now())
    }

    pub fn generate_skewed<const N: usize>(&self, time: u64) -> SkewdIter<'_, N> {
        let basestep = time / self.step - (self.skew as u64);
        SkewdIter {
            totp: self,
            basestep,
            i: 0,
        }
    }

    #[inline(always)]
    pub fn generate_current_skewed<const N: usize>(&self) -> SkewdIter<'_, N> {
        self.generate_skewed(system_now())
    }

    #[inline(always)]
    pub fn sign<const N: usize>(&self, time: u64, nonce: impl AsRef<[u8]>) -> [u8; N] {
        <[u8; N]>::try_from(&hmac(self.generate::<N>(time), nonce)[..N]).unwrap()
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
        for token in self.generate_skewed(time) {
            if f(&token) {
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
        for token in self.generate_skewed::<N>(time) {
            if &<[u8; N]>::try_from(&hmac(token, nonce)[..N]).unwrap() == sig {
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

pub struct SkewdIter<'s, const N: usize> {
    totp: &'s Totp,
    basestep: u64,
    i: usize,
}

impl<'s, const N: usize> Iterator for SkewdIter<'s, N> {
    type Item = [u8; N];

    fn next(&mut self) -> Option<Self::Item> {
        let SkewdIter { totp, basestep, i } = self;
        if *i < (totp.skew as usize) * 2 {
            let step_time = (*basestep + (*i as u64)) * (totp.step as u64);
            *i += 1;
            Some(totp.generate(step_time))
        } else {
            None
        }
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
