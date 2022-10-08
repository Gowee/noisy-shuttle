**❗ Patched edition for RFC8998 ❗**   
Still the same idea, with RFC8998 TLS1.3_SM4_GCM_SM3 as cipher suite / SM2 as KeyShare curve hardcoded as suggested [here](https://github.com/net4people/bbs/issues/129#issuecomment-1272289638). 

Not serious. Just works. No maintenance.

# noisy-shuttle

[![Build](https://github.com/Gowee/noisy-shuttle/actions/workflows/build.yml/badge.svg)](https://github.com/Gowee/noisy-shuttle/actions/workflows/build.yml)
[![GitHub Release](https://img.shields.io/github/release/Gowee/noisy-shuttle.svg?style=flat)]()  

noisy-shuttle establishes an AEAD-encrypted secure tunnel with forward secrecy for circumventing Internet censorship. It is designed  to be indistinguishable from TLS traffic with any chosen website for camouflage by copying authentic TLS handshake messages. 

A shuttle server authenticates clients based on tokens piggybacked by some fields of TLS ClientHello and falling back to dumb relay when authentication failed, preventing [active probing](https://gfw.report/blog/ss_advise/en/).

It is inspired by the brilliant idea of [shadow-tls](https://github.com/ihciah/shadow-tls) and built upon [snow](https://github.com/mcginty/snow) (the Rust implementation of [Noise](http://noiseprotocol.org/) protocol).

<!-- ## Core Idea
Internet censorship nowadays involves with passive analysis of traffic and [active probes](https://gfw.report/blog/ss_advise/en/) targetting at servers providing tunneling/proxy services. shadowsocks [manages](https://github.com/shadowsocks/shadowsocks-org/issues/196) to be indistinguishable by making its traffic look as random as possible. It works pretty well even though there is rumor that network traffic of unidentified protocols are possibly suspected and hence intereven 
Like [trojan](https://github.com/trojan-gfw/trojan), noisy-shuttle aims at making its traffic indistinguishable from typical TLS. But instead of setting up a TLS server with a certificate, noisy-shuttle client and server copies TLS handshakes from a widely-used camouflage website. So by handshaking once, we 
noisy-shuttle is essentially shadow-tls + trojan + shadowsocks. -->

## Features
<!-- ✨ -->
- Eavesdropper-verifiable authentic TLS handshakes with any chosen camouflage website, requiring no certificates
  - Basically indistinguishable from legit TLS traffic

- PSK-based covert authentication piggybacked by TLS client random and session id field
  - Immune to active probes by falling back to dumb relay between a malicious client and the camouflage website

- AEAD encrypted traffic with forward secrecy via ECDHE
  - Never worry about the traffic being recorded by the big brother for long

- Customizable TLS client fingerprints specified via Cli option
  - Replicate any fingerprints listed in https://tlsfingerprint.io exactly

## Handshaking procedures
- shuttle client contrives a legit TLS ClientHello and sends it to shuttle server. Unlike in a typical TLS handshake, the client random and session id field of the ClientHello totaling 64 bytes, which should have been randomly generated, are filled with an ephemeral X25519 public key and an AEAD tag as a part of the Noise [NNPsk0 handshake](https://noiseexplorer.com/patterns/NNpsk0/). And then it proceeds to perform real TLS handshakes with the special ClientHello as typical.
- When shuttle server received a ClientHello, it tries to pull the public key and the AEAD tag from the ClientHello and authenticate them with Noise against a pre-shared key. shuttle server then forwards the ClientHello to a camouflage website and relays subsequent TLS handshake messages between shuttle client and the camouflage server until TLS handshaking is done.
- If the client is successfully authenticated previously, shuttle server sends back a corresponding public key and an AEAD tag as a part of the Noise NNPsk0 handshake and transmutes the connection into a Noise-encrypted tunnel—otherwise, shuttle server keeping relaying traffic dumbly between the unidentified client and the camouflage server.
- After finishing TLS handshakes, shuttle client pulls the public key and the AEAD tag replied by shuttle server from the connection. Till now, an ECDHE key exchange is done between shuttle client and shuttle server. Then shuttle client also transmutes the connection into a Noise-encrypted tunnel. From the point of view of an eavesdropper, the whole procedure is authentic and verifiable TLS handshakes between shuttle client and a camouflage website.

## Cli

**Server:**
```sh
# server               listen_addr   camouflage_addr   password
./noisy-shuttle server 0.0.0.0:443 www.example.com:443 Teap0taa -v
```

`camouflage_addr` is to where TLS handshaking requests from clients are forwarded and from where responses are forwarded backed to clients.
Typically, it should be a well-known website that looks "innocent". Its port CANNOT be omitted. 

**Client:**
```sh
# client                listen_addr        remote_addr             sni        password
./noisy-shuttle client 127.0.0.1:1080 server.addr.example:443 www.example.com Teap0taa -v
```

The client would serve a SOCKS5/HTTP (adaptive) proxy at `listen_addr`.

`remote_addr` is where the shuttle server is located.

`sni` should match `camouflage_addr` specified server-side.

## FAQ for the patched edition

### Where to find a RFC8998 compatible website for camouflage?
[Feel lucky](https://www.google.com/search?q=TLS1.3_SM4_GCM_SM3)

### It is fine to use a standard TLS server without RFC8998 support for camouflage?
Yes. The ServerHello is hardcoded if the client is authenticated.

Otherwise it fallbacks to forwarding traffic to the camouflage server, in which case, active probing would reveal the server does not actually support RFC8998. But, never mind, since this implementation is not serious, leaving many other characteristics to be distinguished.

<!--
**Or optionally specifying a TLS fingerprint ([chrome](https://tlsfingerprint.io/id/e47eae8f8c4887b6)):**
```sh
./noisy-shuttle client 127.0.0.1:1080 server.addr.example:443 www.example.com Teap0taa --tls-ja3 769,2570-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,2570-0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-2570-21,2570-29-23-24,0 --tls-alpn h2,http/1.1 --tls-sigalgos 1027,2052,1025,1283,2053,1281,2054,1537 --tls-versions 2570,772,771 --tls-keyshare 2570
```
-->

<!--
Example fingerprints:

https://tlsfingerprint.io/id/e47eae8f8c4887b6: `--tls-ja3 769,2570-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,2570-0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-2570-21,2570-29-23-24,0 -p 1 --tls-alpn h2,http/1.1 --tls-sigalgos 1027,2052,1025,1283,2053,1281,2054,1537 --tls-versions 2570,772,771 --tls-keyshare 2570,29`


- Some mobile browser: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-17513-21,29-23-24,0`
- Google Chrome: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`
-->

## TODO
- [ ] connection multiplex or connection reuse?
- [ ] Embed `e, ee` into server-side CCS in TLS 1.2
- [x] Handle TLS1.3 response from camouflage server properly
- [ ] Elligator for public key
- [ ] Utilize Keyshare?
- [x] Specify TLS fingerprint (JA3)
- [x] TLS GREASE
- [ ] Configurable actions for unauthenticated client
- [ ] Random packet padding and even packets
