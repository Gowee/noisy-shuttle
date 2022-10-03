use once_cell::sync::Lazy;
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::error;
use ring::rand::SystemRandom;

use std::mem;

const SEED_MAX_BYTES: usize = 48; // ring

// Ref: https://stackoverflow.com/questions/69414467/how-to-make-layout-of-struct-linear
//   There is no "shuffling", and what the compiler does is an implementation detail, but currently
//   it simply orders the fields largest-first. This reduces the size of the structure
//   (by limiting padding) without changing its semantics, or requiring the developer to mess with
//   the "logical" order of the structure.

struct PatchedEphemeralPrivateKey {
    private_key: EcSeed,
    _algorithm_ref: usize, //&'static Algorithm,
}

struct EcSeed {
    bytes: [u8; SEED_MAX_BYTES],
    _curve_ref: usize, // &'static Curve,
    #[allow(dead_code)]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) cpu_features: CpuFeatures, // cpu::Features,
}

struct CpuFeatures(());

pub trait EphemeralPrivateKeyDangerousExt {
    unsafe fn get_inner_mut(&mut self) -> &mut [u8; SEED_MAX_BYTES];
    unsafe fn get_inner(&self) -> &[u8; SEED_MAX_BYTES];
    unsafe fn set_inner(&mut self, value: &[u8]);
    unsafe fn clone(&self) -> Self;
    unsafe fn x25519_from_bytes(s: &[u8]) -> Result<EphemeralPrivateKey, error::Unspecified>;
}

impl EphemeralPrivateKeyDangerousExt for EphemeralPrivateKey {
    unsafe fn get_inner_mut(&mut self) -> &mut [u8; SEED_MAX_BYTES] {
        &mut mem::transmute::<&mut EphemeralPrivateKey, &mut PatchedEphemeralPrivateKey>(self)
            .private_key
            .bytes
    }

    unsafe fn get_inner(&self) -> &[u8; SEED_MAX_BYTES] {
        &mem::transmute::<&EphemeralPrivateKey, &PatchedEphemeralPrivateKey>(self)
            .private_key
            .bytes
    }

    unsafe fn set_inner(&mut self, value: &[u8]) {
        let l = value.len();
        assert!(l <= SEED_MAX_BYTES);
        self.get_inner_mut()[0..l].copy_from_slice(&value);
    }

    unsafe fn clone(&self) -> Self {
        let raw = mem::transmute::<
            &EphemeralPrivateKey,
            &[u8; mem::size_of::<EphemeralPrivateKey>()],
        >(self);
        let cloned = raw.clone();
        mem::transmute::<[u8; mem::size_of::<EphemeralPrivateKey>()], EphemeralPrivateKey>(cloned)
    }

    unsafe fn x25519_from_bytes(privkey: &[u8]) -> Result<Self, error::Unspecified> {
        static TEMPLATE: Lazy<EphemeralPrivateKey> =
            Lazy::new(|| EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap());
        let mut this = TEMPLATE.clone();
        this.set_inner(&privkey[..32]);
        Ok(this)
    }
}

#[cfg(test)]
mod test {
    use super::EphemeralPrivateKeyDangerousExt;

    #[test]
    fn test_x25519_back_and_forth() -> Result<(), ring::error::Unspecified> {
        let group = &ring::agreement::X25519;
        let rng = ring::rand::SystemRandom::new();
        let mut e = ring::agreement::EphemeralPrivateKey::generate(group, &rng)?;
        let pub1 = e.compute_public_key()?;
        let pri = unsafe { e.get_inner() };
        println!("pri: {:x?}", &pri);
        println!("pub: {:?}", &pub1);
        // unsafe { *e.get_inner_mut() = *pri; }
        unsafe { e.set_inner(&<[u8; 32]>::try_from(&pri[..32]).unwrap()) };
        let pub2 = e.compute_public_key()?;
        assert_eq!(pub2.as_ref(), pub1.as_ref());
        assert_eq!(format!("{:?}", pub2), format!("{:?}", pub1));
        Ok(())
    }

    #[test]
    fn test_x25519_from_bytes() -> Result<(), ring::error::Unspecified> {
        let group = &ring::agreement::X25519;
        let rng = ring::rand::SystemRandom::new();
        let e1 = ring::agreement::EphemeralPrivateKey::generate(group, &rng)?;
        let e2 =
            unsafe { ring::agreement::EphemeralPrivateKey::x25519_from_bytes(e1.get_inner()) }?;
            println!("e1: {:x?}", unsafe{e1.get_inner()} );
            println!("e2: {:x?}", unsafe {e2.get_inner()} );
        assert_eq!(unsafe { e2.get_inner() }, unsafe { e1.get_inner() });
        Ok(())
    }
}
