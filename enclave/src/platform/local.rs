//! The local platform: an ordinary process. The attestation document is unsigned (protocol.md
//! 4.2), the listener is TCP `0.0.0.0:8080` and providers are reached by a direct TCP
//! connection. No attestation verifies such a node, so the user keys it holds are of custody
//! `operator`. An app accepts a local document only in a debug build or against a server
//! target its signed program lists for operator custody (protocol.md 4.4).

use std::time::{SystemTime, UNIX_EPOCH};

use credential_enclave_protocol::encoding::{b64u, to_json};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};

use super::{Listener, Measurement, Platform, PlatformError, Stream, LISTEN_PORT};

/// The local platform.
pub struct LocalPlatform;

/// `UTF-8(JSON {"v":1,"platform":"local","binding":b64u(binding),"nonce":b64u,"time_ms":n})`.
#[derive(Serialize)]
struct LocalDocument {
    v: u8,
    platform: &'static str,
    binding: String,
    nonce: String,
    time_ms: u64,
}

/// The unsigned local attestation document over `user_data` (the binding) and `nonce`.
pub fn local_document(user_data: &[u8], nonce: &[u8], time_ms: u64) -> Vec<u8> {
    to_json(&LocalDocument {
        v: 1,
        platform: "local",
        binding: b64u(user_data),
        nonce: b64u(nonce),
        time_ms,
    })
}

/// The system time in Unix epoch milliseconds.
pub fn system_time_ms() -> Result<u64, PlatformError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformError("the system clock is before the Unix epoch"))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| PlatformError("the system clock is out of range"))
}

/// Kernel randomness.
pub fn kernel_random(out: &mut [u8]) -> Result<(), PlatformError> {
    getrandom::getrandom(out).map_err(|_| PlatformError("the kernel random source failed"))
}

impl Platform for LocalPlatform {
    fn name(&self) -> &'static str {
        "local"
    }

    fn custody(&self) -> &'static str {
        "operator"
    }

    fn measurement(&self) -> Option<Measurement> {
        None
    }

    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Ok(local_document(user_data, nonce, system_time_ms()?))
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError> {
        kernel_random(out)
    }

    fn trusted_time_ms(&self) -> Result<u64, PlatformError> {
        system_time_ms()
    }

    async fn listen(&self) -> Result<Listener, PlatformError> {
        TcpListener::bind(("0.0.0.0", LISTEN_PORT))
            .await
            .map(Listener::Tcp)
            .map_err(|_| PlatformError("cannot listen on TCP 0.0.0.0:8080"))
    }

    async fn connect(&self, host: &str, port: u16) -> Result<Stream, PlatformError> {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|_| PlatformError("cannot connect to the provider"))?;
        stream
            .set_nodelay(true)
            .map_err(|_| PlatformError("cannot configure the provider connection"))?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_enclave_protocol::encoding::b64u_decode;

    #[test]
    fn the_local_document_has_the_form_of_protocol_4_2() {
        let document = local_document(b"binding", &[7u8; 32], 1234);
        assert_eq!(
            String::from_utf8(document).unwrap(),
            format!(
                "{{\"v\":1,\"platform\":\"local\",\"binding\":\"{}\",\"nonce\":\"{}\",\"time_ms\":1234}}",
                b64u(b"binding"),
                b64u(&[7u8; 32])
            )
        );
    }

    #[test]
    fn the_platform_binds_user_data_and_nonce_into_its_document() {
        let platform = LocalPlatform;
        let document =
            Platform::attestation(&platform, b"user data", b"nonce-nonce-nonce").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&document).unwrap();
        assert_eq!(value["platform"], "local");
        assert_eq!(
            b64u_decode(value["binding"].as_str().unwrap()).unwrap(),
            b"user data"
        );
        assert_eq!(
            b64u_decode(value["nonce"].as_str().unwrap()).unwrap(),
            b"nonce-nonce-nonce"
        );
        assert!(value["time_ms"].as_u64().unwrap() > 1_700_000_000_000);
        assert_eq!(Platform::name(&platform), "local");
        assert_eq!(Platform::custody(&platform), "operator");
        assert_eq!(Platform::measurement(&platform), None);
    }

    #[test]
    fn random_bytes_differ_between_calls() {
        let platform = LocalPlatform;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        Platform::fill_random(&platform, &mut first).unwrap();
        Platform::fill_random(&platform, &mut second).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 32]);
    }
}
