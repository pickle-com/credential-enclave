//! The nitro platform: a process inside an AWS Nitro enclave. Attestation comes from the Nitro
//! Secure Module (`/dev/nsm`), the listener is vsock port 8080 and providers are reached through
//! the egress relay of the parent instance (vsock CID 3, port 8443).
//!
//! The platform itself is compiled on Linux only. The pure helpers of this file (the timestamp
//! and the measurement of an attestation document, the egress relay handshake) are also
//! compiled for tests on other systems.

use credential_enclave_protocol::attestation::read_unverified_nitro_document;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Measurement, PlatformError};

#[cfg(target_os = "linux")]
pub use enclave::NitroPlatform;

const UNREADABLE: PlatformError =
    PlatformError("the attestation document of the NSM cannot be read");

/// The `timestamp` (Unix epoch milliseconds) of a Nitro attestation document of this node.
///
/// The document is read by the attestation module of the protocol crate, the reader every
/// verifier of a node uses. Its signature is not verified here: the node reads a document it
/// received from its own `/dev/nsm`. A document a peer sent is verified by `crate::attest`.
pub fn attestation_timestamp(document: &[u8]) -> Result<u64, PlatformError> {
    read_unverified_nitro_document(document)
        .map(|document| document.timestamp_ms)
        .map_err(|_| UNREADABLE)
}

/// The measurement of this node: PCR0, PCR1 and PCR2 of a Nitro attestation document it
/// received from its own `/dev/nsm`.
///
/// A PCR that is all zero is the measurement of a debug-mode enclave, whose memory the parent
/// instance can read. That is a failure here: a node does not start in such an enclave.
pub fn attestation_measurement(document: &[u8]) -> Result<Measurement, PlatformError> {
    let document = read_unverified_nitro_document(document).map_err(|_| UNREADABLE)?;
    if document.is_debug_mode() {
        return Err(PlatformError(
            "a measurement is all zero: the enclave runs in debug mode",
        ));
    }
    Ok(Measurement {
        pcrs: [document.pcr0, document.pcr1, document.pcr2],
    })
}

/// Asks the egress relay of the parent instance for a pipe to `host:port`: sends the line
/// `CONNECT {host}:{port}\n` and expects the line `OK\n`. After that the connection carries the
/// bytes of the provider connection (TLS ends inside the node).
pub async fn open_tunnel<S>(stream: &mut S, host: &str, port: u16) -> Result<(), PlatformError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let valid_host = !host.is_empty()
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        });
    if !valid_host {
        return Err(PlatformError("the provider host is not a DNS name"));
    }
    let refused = PlatformError("the egress relay refused the connection");
    stream
        .write_all(format!("CONNECT {host}:{port}\n").as_bytes())
        .await
        .map_err(|_| refused)?;
    stream.flush().await.map_err(|_| refused)?;
    let mut line = Vec::with_capacity(4);
    loop {
        let byte = stream.read_u8().await.map_err(|_| refused)?;
        if byte == b'\n' {
            break;
        }
        line.push(byte);
        if line.len() > 8 {
            return Err(refused);
        }
    }
    if line != b"OK" {
        return Err(refused);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod enclave {
    use std::sync::Mutex;

    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

    use super::{attestation_measurement, attestation_timestamp, open_tunnel};
    use crate::platform::local::kernel_random;
    use crate::platform::{Listener, Measurement, Platform, PlatformError, Stream, LISTEN_PORT};

    /// The vsock CID of the parent instance.
    const PARENT_CID: u32 = 3;
    /// The vsock port of the egress relay in the host program.
    const EGRESS_PORT: u32 = 8443;
    /// The kernel file that names the active hardware random source.
    const RNG_CURRENT: &str = "/sys/class/misc/hw_random/rng_current";
    /// The hardware random source of the Nitro Secure Module.
    const RNG_NSM: &str = "nsm-hwrng";

    /// The descriptor of `/dev/nsm`, closed when the value is dropped.
    struct Nsm(i32);

    impl Nsm {
        fn document(
            &self,
            user_data: Option<&[u8]>,
            nonce: Option<&[u8]>,
        ) -> Result<Vec<u8>, PlatformError> {
            let request = Request::Attestation {
                user_data: user_data.map(|bytes| bytes.to_vec().into()),
                nonce: nonce.map(|bytes| bytes.to_vec().into()),
                public_key: None,
            };
            match nsm_process_request(self.0, request) {
                Response::Attestation { document } => Ok(document),
                _ => Err(PlatformError(
                    "the NSM did not return an attestation document",
                )),
            }
        }
    }

    impl Drop for Nsm {
        fn drop(&mut self) {
            nsm_exit(self.0);
        }
    }

    /// The nitro platform. Holds the descriptor of `/dev/nsm` for the life of the process, and
    /// the measurement of the enclave it runs in.
    pub struct NitroPlatform {
        nsm: Mutex<Nsm>,
        measurement: Measurement,
    }

    impl NitroPlatform {
        /// Opens the platform. Fails when the kernel random source is not `nsm-hwrng`, when
        /// `/dev/nsm` cannot be opened, or when the enclave runs in debug mode (a PCR of its
        /// own attestation document is all zero): the node does not start outside a
        /// production enclave.
        pub fn open() -> Result<Self, PlatformError> {
            let current = std::fs::read_to_string(RNG_CURRENT)
                .map_err(|_| PlatformError("cannot read the active hardware random source"))?;
            if current.trim() != RNG_NSM {
                return Err(PlatformError(
                    "the active hardware random source is not nsm-hwrng",
                ));
            }
            let descriptor = nsm_init();
            if descriptor < 0 {
                return Err(PlatformError("cannot open /dev/nsm"));
            }
            let nsm = Nsm(descriptor);
            let measurement = attestation_measurement(&nsm.document(None, None)?)?;
            Ok(NitroPlatform {
                nsm: Mutex::new(nsm),
                measurement,
            })
        }

        fn document(
            &self,
            user_data: Option<&[u8]>,
            nonce: Option<&[u8]>,
        ) -> Result<Vec<u8>, PlatformError> {
            self.nsm
                .lock()
                .map_err(|_| PlatformError("the NSM descriptor lock is poisoned"))?
                .document(user_data, nonce)
        }
    }

    impl Platform for NitroPlatform {
        fn name(&self) -> &'static str {
            "nitro"
        }

        fn custody(&self) -> &'static str {
            "enclave"
        }

        fn measurement(&self) -> Option<Measurement> {
            Some(self.measurement)
        }

        fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError> {
            self.document(Some(user_data), Some(nonce))
        }

        fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError> {
            kernel_random(out)
        }

        fn trusted_time_ms(&self) -> Result<u64, PlatformError> {
            attestation_timestamp(&self.document(None, None)?)
        }

        async fn listen(&self) -> Result<Listener, PlatformError> {
            VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, u32::from(LISTEN_PORT)))
                .map(Listener::Vsock)
                .map_err(|_| PlatformError("cannot listen on vsock port 8080"))
        }

        async fn connect(&self, host: &str, port: u16) -> Result<Stream, PlatformError> {
            let mut stream = VsockStream::connect(VsockAddr::new(PARENT_CID, EGRESS_PORT))
                .await
                .map_err(|_| PlatformError("cannot reach the egress relay of the parent"))?;
            open_tunnel(&mut stream, host, port).await?;
            Ok(Box::new(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real document as a node receives it from its own NSM at boot, in a debug-mode
    /// enclave (2026-10-01): the payload is an indefinite-length map, PCR0, PCR1 and PCR2 are
    /// zero, user data and nonce are null.
    const BOOT_DOCUMENT: &[u8] =
        include_bytes!("../../../protocol/tests/fixtures/nitro-attestation-document-boot.cbor");
    /// A real document of a production-mode enclave (2026-10-01).
    const OPERATIONAL_DOCUMENT: &[u8] = include_bytes!(
        "../../../protocol/tests/fixtures/nitro-attestation-document-operational.cbor"
    );

    fn pcr(text: &str) -> [u8; 48] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    #[test]
    fn the_clock_reads_the_timestamp_of_a_real_document() {
        // The form the NSM writes: a payload map of indefinite length.
        assert_eq!(
            &BOOT_DOCUMENT[..11],
            &[0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x11, 0x01, 0xbf]
        );
        assert_eq!(attestation_timestamp(BOOT_DOCUMENT), Ok(1_790_825_991_147));
        assert_eq!(
            attestation_timestamp(OPERATIONAL_DOCUMENT),
            Ok(1_790_827_255_513)
        );
        // With the COSE_Sign1 tag in front.
        let mut tagged = vec![0xd2];
        tagged.extend_from_slice(BOOT_DOCUMENT);
        assert_eq!(attestation_timestamp(&tagged), Ok(1_790_825_991_147));
    }

    #[test]
    fn the_measurement_is_pcr0_pcr1_and_pcr2_of_a_real_document() {
        assert_eq!(
            attestation_measurement(OPERATIONAL_DOCUMENT),
            Ok(Measurement {
                pcrs: [
                    pcr("904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47"),
                    pcr("4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"),
                    pcr("a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44"),
                ]
            })
        );
    }

    #[test]
    fn a_debug_mode_enclave_has_no_measurement() {
        // The three PCRs of the boot document are all zero: the node does not start. The
        // failure is this judgment, not a document that could not be read.
        assert_eq!(
            attestation_measurement(BOOT_DOCUMENT),
            Err(PlatformError(
                "a measurement is all zero: the enclave runs in debug mode"
            ))
        );
        // One all-zero PCR among the three is enough.
        let pcr1 = OPERATIONAL_DOCUMENT
            .windows(4)
            .position(|window| window == [0x4b, 0x4d, 0x5b, 0x36])
            .unwrap();
        let mut debug = OPERATIONAL_DOCUMENT.to_vec();
        debug[pcr1..pcr1 + 48].fill(0);
        assert_eq!(
            attestation_measurement(&debug),
            Err(PlatformError(
                "a measurement is all zero: the enclave runs in debug mode"
            ))
        );
        // The timestamp of that document is still read: the clock does not depend on the
        // measurement.
        assert_eq!(attestation_timestamp(&debug), Ok(1_790_827_255_513));
    }

    #[test]
    fn a_document_that_is_not_one_is_not_read() {
        for document in [
            &[][..],
            &BOOT_DOCUMENT[..BOOT_DOCUMENT.len() / 2],
            // An array that is not the array of four.
            &[0x9f, 0xff],
            &[0x83, 0x40, 0xa0, 0x40],
            b"not a document",
        ] {
            assert_eq!(attestation_timestamp(document), Err(UNREADABLE));
            assert_eq!(attestation_measurement(document), Err(UNREADABLE));
        }
        // The payload map without its break: the break is the last byte of the payload, 98
        // bytes before the end (the signature and its head follow it).
        assert_eq!(BOOT_DOCUMENT[BOOT_DOCUMENT.len() - 99], 0xff);
        let mut cut = BOOT_DOCUMENT[..BOOT_DOCUMENT.len() - 99].to_vec();
        cut.extend_from_slice(&BOOT_DOCUMENT[BOOT_DOCUMENT.len() - 98..]);
        // The payload byte string is one byte shorter now: 0x1100 instead of 0x1101.
        assert_eq!(&cut[7..10], &[0x59, 0x11, 0x01]);
        cut[9] = 0x00;
        assert_eq!(attestation_timestamp(&cut), Err(UNREADABLE));
    }

    #[tokio::test]
    async fn the_egress_handshake_sends_connect_and_accepts_ok() {
        let (mut near, mut far) = tokio::io::duplex(256);
        let relay = tokio::spawn(async move {
            let mut line = Vec::new();
            loop {
                let byte = far.read_u8().await.unwrap();
                line.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            far.write_all(b"OK\nrest").await.unwrap();
            (line, far)
        });
        open_tunnel(&mut near, "oauth2.googleapis.com", 443)
            .await
            .unwrap();
        let (line, _far) = relay.await.unwrap();
        assert_eq!(line, b"CONNECT oauth2.googleapis.com:443\n");
        // The bytes after the reply line stay in the pipe for the TLS layer.
        let mut rest = [0u8; 4];
        near.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"rest");
    }

    #[tokio::test]
    async fn the_egress_handshake_fails_on_err_and_on_a_host_that_is_not_a_name() {
        let (mut near, mut far) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let _ = far.read(&mut buffer).await;
            let _ = far.write_all(b"ERR\n").await;
            far
        });
        assert!(open_tunnel(&mut near, "evil.example", 443).await.is_err());

        let (mut near, _far) = tokio::io::duplex(256);
        assert!(open_tunnel(&mut near, "host\nCONNECT other:443", 443)
            .await
            .is_err());
        assert!(open_tunnel(&mut near, "", 443).await.is_err());
    }
}
