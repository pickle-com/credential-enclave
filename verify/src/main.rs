//! Verifies the attestation of the running nodes of the credential enclave.
//!
//! ```text
//! credential-enclave-verify --url https://{api host} --measurements out/measurements.json
//! credential-enclave-verify --url https://{api host} --pcr0 {hex} --pcr1 {hex} --pcr2 {hex}
//! credential-enclave-verify --document {file} --nonce {hex} --measurements out/measurements.json
//! ```
//!
//! That the running nodes are the published source is verified in two halves. The first half
//! is the build: `build/build.sh eif` builds the source and writes its measurements (PCR0,
//! PCR1 and PCR2) to `out/measurements.json`, the file every GitHub release carries. This tool
//! is the second half: it asks the running service for the attestation document of every node
//! and compares.
//!
//! With `--url` the tool sends one request without a credential,
//! `GET {url}/api/credential-enclave/attestation?nonce={nonce}`, with a nonce of 32 random
//! bytes in base64url without padding. The response is
//! `{"nodes":[{"v":1,"platform":"nitro","document":"<base64url>","node":"<node id>","release":"..."}]}`
//! or that array alone. With `--document` and `--nonce` the tool reads one stored Nitro
//! attestation document (raw CBOR bytes) instead.
//!
//! The checks on a Nitro attestation document, in this order:
//!
//! | Check | What passes |
//! | --- | --- |
//! | `document form` | the document is a COSE_Sign1 structure with the ES384 header around an attestation payload |
//! | `certificate chain` | the chain leads from the certificate of the document to the AWS Nitro Enclaves Root-G1 compiled into the tool, at the time of the document |
//! | `signature` | the ECDSA P-384 signature verifies under the key of that certificate |
//! | `nonce` | the document carries the nonce of this request |
//! | `production mode` | none of PCR0, PCR1 and PCR2 is all zero (all zero is a debug-mode enclave) |
//! | `pcr0`, `pcr1`, `pcr2` | each equals the expected value |
//! | `binding` | the user data of the document is the binding of a node: its signing key, its sealing key and its release |
//! | `node key` | the signing key of the binding is the `node` of the response |
//!
//! The first four are `verify_nitro_document` of the protocol crate and the binding is read by
//! its `read_binding`: the code a node runs when it verifies a peer. The certificate chain is
//! validated at the time the document states, because the certificate of a document is valid
//! for about three hours. The nonce is what shows that a document was made for this request.
//!
//! A node of the platform `local` runs outside an enclave and no attestation verifies it. It
//! is a failure unless `--allow-local` is given.
//!
//! The report goes to the standard output: a head, one block per node with what the document
//! states and every check, and the summary as the last line. Without expected measurements
//! the three comparisons do not run, and the head and the summary say that nothing was
//! compared. Messages about a run without a result go to the standard error.
//!
//! Exit status: 0 when every node passed, 1 when at least one node failed, 2 when there is no
//! result (the arguments, a file, the network, the HTTP status or the response).

#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod arguments;
mod evaluate;
mod fetch;
mod render;

use std::io::Write;
use std::process::ExitCode;

use arguments::{Arguments, Command, Expected, Measurements, Source, USAGE};
use render::{Report, EXIT_NO_RESULT, EXIT_PASSED};

/// The end of a run: the exit status and what goes to the standard output and to the standard
/// error.
struct End {
    status: u8,
    output: String,
    error: String,
}

impl End {
    /// A run without a result.
    fn no_result(message: &str) -> End {
        End {
            status: EXIT_NO_RESULT,
            output: String::new(),
            error: format!("credential-enclave-verify: {message}\n"),
        }
    }
}

/// Writes the text of the tool to the standard output or the standard error. These two calls
/// are the only output of the program.
fn write_out(text: &str) {
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
}

fn write_error(text: &str) {
    let _ = std::io::stderr().lock().write_all(text.as_bytes());
}

fn main() -> ExitCode {
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(argument) => arguments.push(argument),
            Err(_) => {
                write_error("credential-enclave-verify: an argument is not valid UTF-8\n");
                return ExitCode::from(EXIT_NO_RESULT);
            }
        }
    }
    let end = run(&arguments);
    write_out(&end.output);
    write_error(&end.error);
    ExitCode::from(end.status)
}

fn run(arguments: &[String]) -> End {
    match arguments::parse(arguments) {
        Ok(Command::Help) => End {
            status: EXIT_PASSED,
            output: USAGE.to_string(),
            error: String::new(),
        },
        Ok(Command::Verify(arguments)) => match verify(&arguments) {
            Ok(end) => end,
            Err(message) => End::no_result(&message),
        },
        Err(message) => End::no_result(&format!("{message}\n\n{USAGE}")),
    }
}

/// Runs the verification. An error is a run without a result.
fn verify(arguments: &Arguments) -> Result<End, String> {
    let expected = match &arguments.expected {
        Expected::Nothing => None,
        Expected::File(path) => {
            let content = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
            Some(Measurements::of_file(path, &content)?)
        }
        Expected::Values(pcrs) => Some(Measurements::of_command_line(*pcrs)),
    };
    let expected = expected.as_ref();

    let (source, nonce, nodes) = match &arguments.source {
        Source::Service { url } => {
            let nonce = fetch::fresh_nonce()?.to_vec();
            let body = fetch::get(&fetch::request_address(url, &nonce))?;
            let nodes = evaluate::entries_of_response(&body)?
                .iter()
                .map(|entry| {
                    evaluate::evaluate_entry(entry, &nonce, expected, arguments.allow_local)
                })
                .collect();
            (fetch::route_address(url), nonce, nodes)
        }
        Source::Document { path, nonce } => {
            let document = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
            let node = evaluate::evaluate_document(&document, nonce, expected);
            (path.clone(), nonce.clone(), vec![node])
        }
    };

    let report = Report {
        source: &source,
        nonce: &nonce,
        expected,
        nodes: &nodes,
    };
    Ok(End {
        status: report.exit_status(),
        output: report.render(),
        error: String::new(),
    })
}
