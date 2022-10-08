use hex_literal::hex;

use rustls::internal::msgs::{
    base::{Payload, PayloadU16},
    codec::Codec,
    handshake::{ClientExtension, ServerExtension},
    message::{Message, MessagePayload},
};

use crate::utils::{parse_tls_plain_message, TlsMessageExt};

// lazy_static! {
//     pub static ref RFC8998_CLIENT_HELLO_BOILERPLATE: Message = load_rfc8998_client_hello_boilerplate();
// }

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
    003300470045002900 41 0425b84ede0185816959c7498398203011d46274d4b1bc06c630da6fd8e1e474ed713bb2f48301c880dec0abbd9d6c45ae7a7cbc511c2ad34fc3c9a499e8c3c1ea
    ");
    parse_tls_plain_message(&dump).expect("Dump valid")
}

pub fn generate_rfc8998_client_hello(
    client_random: [u8; 32],
    session_id: [u8; 32],
    sm2_point: Vec<u8>,
) -> Message {
    let mut message = load_rfc8998_client_hello_boilerplate();
    let mut chp = message.as_client_hello_payload_mut().unwrap();
    chp.random = client_random.into();
    chp.session_id = session_id.as_slice().into();
    for extension in chp.extensions.iter_mut() {
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
    0033 0045 00290041040af9e9eedb33b97df90dd8af4889a485fda30467cac0badf7a27e87f2c8269e0460b3392d15fbb9e48e89b255358158db2f7872f1e3c3f82357eb66eec0662a5");

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
    if let MessagePayload::Handshake {
        ref mut parsed,
        ref mut encoded,
    } = message.payload
    {
        *encoded = Payload::new(parsed.get_encoding());
    }
}
