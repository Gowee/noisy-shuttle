# noisy-shuttle

A tunnel built upon the brilliant idea of [shadow-tls](https://github.com/ihciah/shadow-tls) with DH key exchange piggybacked by camouflage TLS handshakes.

Inspired by https://github.com/ihciah/shadow-tls.

## JA3 support
The shuttle supports overwriting TLS ClientHello fingerprints specified in [JA3](https://github.com/salesforce/ja3) format.

Examples JA3:

- Some mobile browser: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-17513-21,29-23-24,0`
- Google Chrome: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`


## TODO
- [ ] connection multiplex or connection reuse
- [ ] Embed `e, ee` into server-side CCS in TLS 1.2
- [x] Handle TLS1.3 response from camouflage server properly
- [ ] Elligator for public key
- [ ] Utilize Keyshare?
- [x] Specify TLS fingerprint (JA3)
- [ ] TLS GREASE
- [ ] Configurable actions for unauthenticated client
- [ ] Random packet padding and even packets
