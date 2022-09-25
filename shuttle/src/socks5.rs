// use socks5_protocol::socks5;

// async fn accept_socks5_connection(stream: &mut (impl AsyncRead + AsyncWrite +  Unpin)) -> {
//     if socks5::Version::read(&mut inbound).await?;
//     let s5req = socks5::AuthRequest::read(&mut inbound)
//         .await?;
//     socks5::AuthResponse::new(s5req.select_from(&[socks5::AuthMethod::Noauth]))
//         .write(&mut inbound)
//         .await?;
//     let s5req = socks5::CommandRequest::read(&mut inbound).await.map_err(|e| e.to_io_err())?;
//     if s5req.
// }
