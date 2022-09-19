// //! A simple time-based replay filter
// use lru::LruCache;

// use std::sync::Mutex;
// use std::hash::Hash;

// use crate::totp::Totp;

// #[derive(Debug)]
// pub struct TimeBasedReplayFilter<const TN: usize, TK: Hash + Eq, ID> {
//     seen: Mutex<LruCache<TK, ID>>,
//     totp: Totp,
// }

// impl<const TN: usize, TK: Hash + Eq, ID> TimeBasedReplayFilter<TN, TK, ID> {
//     pub fn new(key: impl AsRef<[u8]>, capacity: usize) -> Self {
//         TimeBasedReplayFilter {
//             seen: Mutex::new(LruCache::new(capacity)),
//             totp: Totp::new(key, 60, 2),
//         }
//     }

//     pub fn find(&self, token: TK, totp_token: [u8; 32]) -> Option<&ID> {
//         if self.totp.verify(totp_token) {}
//     }
// }
