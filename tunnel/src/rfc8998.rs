use hex_literal::hex;

use rustls::{
    internal::msgs::{
        base::{Payload, PayloadU16},
        codec::Codec,
        handshake::{ClientExtension, ServerExtension, ServerName as HsServerName},
        message::{Message, MessagePayload},
    },
    ServerName,
};

use crate::utils::{parse_tls_plain_message, TlsMessageExt};

fn load_rfc8998_client_hello_boilerplate() -> Message {
    let dump = hex!("1603010102 // TLS header
    010000fe0303 // handshake header
    0000000000000000000000000000000000000000000000000000000000000000 // client random
    20 0000000000000000000000000000000000000000000000000000000000000000 // session id
    0004 00c600ff // cipher suites
    01 00 // compression methods
    00b1 // extensions length
    0000001d001b000018726663383939386f6e6c792e626164676d73736c2e636f6d // SNI
    // several extensions
    000a000400020029002300000016000000170000000d0020001e0403050306030708080708080809080a080b080408050806040105010601002b0003020304002d00020101
    // KeyShare: SM2
    003300470045002900 41 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ");
    parse_tls_plain_message(&dump).expect("Dump valid")
}

pub fn generate_rfc8998_client_hello(
    client_random: [u8; 32],
    session_id: [u8; 32],
    server_name: &ServerName,
    sm2_point: Vec<u8>,
) -> Message {
    let sni = match server_name {
        ServerName::DnsName(ref dns_name) => Some(dns_name.as_ref()),
        ServerName::IpAddress(_) => None,
        _ => unreachable!(),
    };
    let mut message = load_rfc8998_client_hello_boilerplate();
    let mut chp = message.as_client_hello_payload_mut().unwrap();
    chp.random = client_random.into();
    chp.session_id = session_id.as_slice().into();
    for extension in chp.extensions.iter_mut() {
        match extension {
            ClientExtension::KeyShare(entries) => {
                entries[0].payload = PayloadU16(sm2_point);
                break;
            }
            ClientExtension::ServerName(inner) => {
                if let Some(sni) = sni {
                    // some types and contruct method are private, just use Codec to create it
                    let mut s = vec![0u8; 3 + sni.len()];
                    // s[0] = 0x00;
                    s[1..3].copy_from_slice(&(sni.len() as u16).to_be_bytes());
                    s[3..].copy_from_slice(sni.as_bytes());
                    inner[0] = HsServerName::read_bytes(&s).expect("not valid server name");
                }
            }
            _ => {}
        }
        if let ClientExtension::KeyShare(entries) = extension {
            entries[0].payload = PayloadU16(sm2_point);
            break;
        }
    }
    update_message_encoded(&mut message);
    message
}

fn load_rfc8998_server_hello_boilerplate() -> Message {
    let dump = hex!("
    16030300 // TLS header
    9b020000970303 // handshake header
    0000000000000000000000000000000000000000000000000000000000000000 // server random
    20 0000000000000000000000000000000000000000000000000000000000000000 // session id
    00c6 // cipher suite
    00 // compression method
    004f // extensions length
    002b00020304 // supported versions
    // KeyShare: SM2
    0033 0045 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    parse_tls_plain_message(&dump).expect("Dump valid")
}

pub fn generate_rfc8998_server_hello(
    server_random: [u8; 32],
    session_id: [u8; 32],
    sm2_point: Vec<u8>,
) -> Message {
    let mut message = load_rfc8998_server_hello_boilerplate();
    let mut shp = message.as_server_hello_payload_mut().unwrap();
    shp.random = server_random.into();
    shp.session_id = session_id.as_slice().into();
    for extension in shp.extensions.iter_mut() {
        if let ServerExtension::KeyShare(entry) = extension {
            entry.payload = PayloadU16(sm2_point);
            break;
        }
    }
    update_message_encoded(&mut message);
    message
}

fn update_message_encoded(message: &mut Message) {
    // payload are stored twice, encoded should also be updated after updating parsed
    if let MessagePayload::Handshake {
        ref mut parsed,
        ref mut encoded,
    } = message.payload
    {
        *encoded = Payload::new(parsed.get_encoding());
    }
}
