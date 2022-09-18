# noisy-shuttle

A tunnel built upon the brilliant idea of [shadow-tls](https://github.com/ihciah/shadow-tls) with DH key exchange piggybacked by camouflage TLS handshakes.

Inspired by https://github.com/ihciah/shadow-tls.

## ✨ Features

- Eavesdropper-verifiable authentic TLS handshakes with any website, requiring no certificates

- PSK-based covert authentication piggybacked by TLS client random and session id field

- Almost fully customizable TLS client fingerprint

- AEAD encrypted traffic with forward secrecy via ECDHE

Example fingerprints:

https://tlsfingerprint.io/id/e47eae8f8c4887b6: `--tls-ja3 769,2570-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,2570-0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-2570-21,2570-29-23-24,0 -p 1 --tls-alpn h2,http/1.1 --tls-sigalgos 1027,2052,1025,1283,2053,1281,2054,1537 --tls-versions 2570,772,771 --tls-keyshare 2570,29`


- Some mobile browser: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-17513-21,29-23-24,0`
- Google Chrome: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`




## TODO
- [ ] connection multiplex or connection reuse
- [ ] Embed `e, ee` into server-side CCS in TLS 1.2
- [x] Handle TLS1.3 response from camouflage server properly
- [ ] Elligator for public key
- [ ] Utilize Keyshare?
- [x] Specify TLS fingerprint (JA3)
- [x] TLS GREASE
- [ ] Configurable actions for unauthenticated client
- [ ] Random packet padding and even packets
