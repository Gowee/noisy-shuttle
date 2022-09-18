use hex_literal::hex;
use ja3_rustls::{is_grease_u16_be, try_regrease_u16_be, Ja3};
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::{
    ClientExtension, ConvertProtocolNameList, HandshakeMessagePayload, HandshakePayload,
    KeyShareEntry, ProtocolNameList, UnknownExtension,
};
use rustls::internal::msgs::message::{Message, MessagePayload};

use tracing::{debug, trace, warn};

use std::collections::HashMap;

use std::sync::Arc;

use crate::try_assign;

const RFC7685_PADDING_TARGET: usize = 512;

/// TLS ClientHello fingerprints
#[derive(Debug, Clone, Default)]
pub struct FingerprintSpec {
    pub ja3: Option<Ja3>,
    pub alpn: Option<Vec<Vec<u8>>>,
    pub signature_algos: Option<Vec<u16>>,
    pub supported_versions: Option<Vec<u16>>,
    pub key_share: Option<Vec<u16>>,
}

impl FingerprintSpec {
    pub fn new() -> Self {
        Default::default()
    }

    // pub fn with_ja3(self, ja3: Ja3) -> Self {
    //     self.ja3 = Some(ja3);
    //     self
    // }

    pub fn is_empty(&self) -> bool {
        self.ja3.is_none()
            && self.alpn.is_none()
            && self.signature_algos.is_none()
            && self.supported_versions.is_none()
            && self.key_share.is_none()
    }

    pub fn overwrite_client_hello(
        &self,
        msg: &mut Message,
        add_empty_if_extension_not_in_message: bool,
        drop_extensions_not_in_ja3: bool,
    ) -> Option<Vec<ExtensionType>> {
        overwrite_client_hello_with_fingerprint_spec(
            msg,
            self,
            add_empty_if_extension_not_in_message,
            drop_extensions_not_in_ja3,
        )
    }

    pub fn get_client_hello_overwriter(
        self: &Arc<Self>,
        add_empty_if_extension_not_in_message: bool,
        drop_extensions_not_in_ja3: bool,
    ) -> Option<impl FnOnce(&mut Message) -> Option<Vec<ExtensionType>>> {
        if self.is_empty() {
            return None;
        }
        let fp = self.clone();
        Some(move |msg: &mut Message| {
            fp.overwrite_client_hello(
                msg,
                add_empty_if_extension_not_in_message,
                drop_extensions_not_in_ja3,
            )
        })
    }
}

// impl From<Ja3> for FingerprintSpec {
//     fn from(ja3:Ja3) -> Self {
//         Self {
//             ja3,
//             alpn: Default::default(),
//             signature_algos: Default::default(),
//             supported_versions: Default::default(),
//             key_share: Default::default(),
//         }
//     }
// }

/// Apply a JA3 fingerprint to a ClientHello [`Message`].
///
/// Cipher suites, curvres, and EC point formats are simply overwritten with the those specified by
/// a JA3. For TLS extensions, the function manages to match the sort order, **optionally** add
/// empty or hardcoded dummy records for those not in message yet but listed in JA3, and
/// **optionally** drop existing ones from client hello payload if they are not present in JA3.
///
/// It returns a list of allowed unsolicited server extensions matched with the updated message.
///
/// # Note
/// It is caller's responsibility to ensure that the message constitutes a valid ClientHello. Otherwise,
/// only the protocol version in the message header is overwritten.
pub fn overwrite_client_hello_with_fingerprint_spec(
    msg: &mut Message,
    fp: &FingerprintSpec,
    add_empty_if_extension_not_in_message: bool,
    drop_extensions_not_in_ja3: bool,
) -> Option<Vec<ExtensionType>> {
    use ExtensionType::*;
    #[allow(unused_mut)]
    let mut allowed_unsolicited_extensions = vec![ExtensionType::RenegotiationInfo];
    trace!(
        "overwrite client hello of {:?} with fingerprint {:?}",
        msg,
        fp
    );
    try_assign!(
        msg.version,
        fp.ja3.as_ref().map(|ja3| ja3.version_to_typed())
    );
    if let MessagePayload::Handshake {
        ref mut parsed,
        ref mut encoded,
    } = msg.payload
    {
        let mut pad_per_rfc7685 = false;
        if let HandshakeMessagePayload {
            payload: HandshakePayload::ClientHello(ref mut chp),
            ..
        } = parsed
        {
            try_assign!(
                chp.cipher_suites,
                fp.ja3.as_ref().map(|ja3| ja3.ciphers_as_typed().collect())
            );
            match &fp.ja3 {
                Some(ja3) => {
                    // try to match extension order
                    let mut new_extensions = Vec::with_capacity(if drop_extensions_not_in_ja3 {
                        ja3.extensions.len()
                    } else {
                        chp.extensions.len()
                    });
                    let mut oldextmap: HashMap<u16, &ClientExtension> = chp
                        .extensions
                        .iter()
                        .map(|extension| (extension.get_type().get_u16(), extension))
                        .collect();
                    for exttyp in ja3
                        .extensions_regreasing_as_typed()
                        .map(|extension_type| extension_type.get_u16())
                    {
                        match oldextmap.remove(&exttyp) {
                            Some(extension) => new_extensions.push(extension.clone()),
                            None => {
                                if !add_empty_if_extension_not_in_message {
                                    continue;
                                }
                                trace!(
                        "ja3 overwiting: missing extension {:?} in original chp, add an dummy one",
                        ExtensionType::from(exttyp));
                                // Some extension expect vectored struct, we cannot just set empty.
                                let extpld = match ExtensionType::from(exttyp) {
                                    // ALPN: http/1.1 + h2
                                    ALProtocolNegotiation => {
                                        panic!("Expect ALPN present in original message if it is listed in JA3")
                                        // allowed_unsolicited_extensions
                                        //     .push(ExtensionType::ALProtocolNegotiation);
                                        // Vec::from(hex!("000c08687474702f312e31026832"))
                                    }
                                    // Renegotiation Info: still empty, but an additional length field
                                    RenegotiationInfo => Vec::from(hex!("00")),
                                    // ALPS: supported ALPN list: h2  (TODO: what is it?)
                                    ExtensionType::Unknown(0x4469) => Vec::from(hex!("0003026832")),
                                    Padding => {
                                        pad_per_rfc7685 = true;
                                        vec![]
                                    }
                                    // Compress Certificate: Rustls does not support it.
                                    // Chrome use 02 00 02 (brotli).
                                    // By setting it non-empty, we risk at TLS negotiation error.
                                    ExtensionType::Unknown(0x001b) => Vec::from(hex!("020002")),
                                    _ => vec![],
                                };
                                let extension = ClientExtension::Unknown(UnknownExtension {
                                    typ: ExtensionType::from(exttyp),
                                    payload: Payload(extpld),
                                });
                                // Codec works fine with UnknownExtension
                                new_extensions.push(extension);
                            }
                        }
                    }
                    if !oldextmap.is_empty() && !drop_extensions_not_in_ja3 {
                        // there might be some extensions in CHP that are not present in ja3
                        trace!("ja3 overwriting: extension {:?} in original chp not present in ja3, appending to end: {}", oldextmap, !drop_extensions_not_in_ja3);
                        new_extensions
                            .extend(oldextmap.into_iter().map(|(_typ, ext)| ext.to_owned()));
                    }
                    chp.extensions = new_extensions;
                }
                None => {}
            }

            // rewrite extension values
            for extension in chp.extensions.iter_mut() {
                use ClientExtension::*;
                match extension {
                    NamedGroups(groups) => {
                        try_assign!(
                            *groups,
                            fp.ja3
                                .as_ref()
                                .map(|ja3| ja3.curves_regreasing_as_typed().collect())
                        );
                    }
                    ECPointFormats(formats) => {
                        try_assign!(
                            *formats,
                            fp.ja3
                                .as_ref()
                                .map(|ja3| ja3.point_formats_as_typed().collect())
                        );
                    }
                    // ALProtocolN
                    Protocols(alpn) => {
                        try_assign!(
                            *alpn,
                            fp.alpn.as_ref().map(|alpn| {
                                ProtocolNameList::from_slices(
                                    &alpn.iter().map(|proto| &proto[..]).collect::<Vec<_>>(),
                                )
                            })
                        );
                    }
                    SupportedVersions(vers) => {
                        try_assign!(
                            *vers,
                            fp.supported_versions.as_ref().map(|vers| vers
                                .iter()
                                .map(|&ver| try_regrease_u16_be(ver).into())
                                .collect())
                        )
                    }
                    SignatureAlgorithms(algos) => {
                        try_assign!(
                            *algos,
                            fp.signature_algos.as_ref().map(|algos| algos
                                .iter()
                                .map(|&algo| try_regrease_u16_be(algo).into())
                                .collect())
                        );
                    }
                    KeyShare(entries) => {
                        if let Some(fpents) = fp.key_share.as_ref() {
                            let mut oldentmap: HashMap<_, _> = entries
                                .iter()
                                .map(|ent| (ent.group.get_u16(), ent))
                                .collect();
                            let mut new_entries = vec![];
                            for &ent in fpents {
                                match oldentmap.remove(&ent) {
                                    Some(entry) => new_entries.push(entry.clone()),
                                    None => {
                                        if !is_grease_u16_be(ent) {
                                            warn!("TLS Key Share of curve {} is not present in original ClientHello. A empty payload is used, which makes traffic look distinctive.", ent);
                                        }
                                        new_entries.push(KeyShareEntry::new(
                                            try_regrease_u16_be(ent).into(),
                                            &[0x00],
                                        ));
                                    }
                                }
                            }
                            // ignore remaining entries in oldentmap, if any
                            *entries = new_entries;
                        }
                    }
                    Unknown(UnknownExtension {
                        typ: ExtensionType::Padding,
                        ref mut payload,
                    }) => {
                        payload.0.clear();
                        pad_per_rfc7685 = true;
                    }
                    _ => {}
                }
            }
        }
        if pad_per_rfc7685 {
            // previous steps ensure padding extension is included already
            // Padding as defined in RFC7685: pad the payload to at least 512 bytes
            // ref: https://datatracker.ietf.org/doc/html/rfc7685#section-4
            let pldlen = parsed.get_encoding().len();
            let padlen = RFC7685_PADDING_TARGET.saturating_sub(pldlen);
            trace!(padlen, "ja3 overwiting: apply rfc7685 padding");
            if padlen != 0 {
                if let HandshakeMessagePayload {
                    payload: HandshakePayload::ClientHello(ref mut chp),
                    ..
                } = parsed
                {
                    for extension in chp.extensions.iter_mut() {
                        if let ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::Padding,
                            payload,
                        }) = extension
                        {
                            payload.0.resize(padlen, 0);
                            break;
                        }
                    }
                }
            }
            // TODO: strip padding if final length >= 512 + 4?
        }
        // Payload are stored twice in struct: one typed and one bytes. Both (or at least the
        // latter) needs overwriting.
        *encoded = Payload::new(parsed.get_encoding());
        if pad_per_rfc7685 && encoded.0.len() >= 512 + 4 {
            debug!("ja3 overwriting: len of client hello msg >= 512 + 4, while padding is still applied ");
        }
    }
    Some(allowed_unsolicited_extensions)
}
