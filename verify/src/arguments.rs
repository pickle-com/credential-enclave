//! The command line of the tool and the expected measurements it names.

use serde_json::Value;

/// The text of `--help`, and what follows the message about an argument that is not understood.
pub const USAGE: &str = "\
usage:
  credential-enclave-verify --url https://{api host} [expected measurements] [--allow-local]
  credential-enclave-verify --document {file} --nonce {hex} [expected measurements]

what is verified, one of:
  --url {address}        the running nodes: the tool sends
                         GET {address}/api/credential-enclave/attestation?nonce={nonce}
                         with a nonce of 32 random bytes and verifies the attestation document
                         of every node of the response
  --document {file}      one stored Nitro attestation document (raw CBOR bytes), with
  --nonce {hex}          the nonce that document was requested with

expected measurements, one of:
  --measurements {file}  the measurements.json of a build (build/build.sh eif) or of a release
  --pcr0 {hex} --pcr1 {hex} --pcr2 {hex}
                         the three values, 96 lowercase hex characters each
  Without expected measurements the tool prints the measurements of the documents and
  compares them with nothing.

  --allow-local          with --url: do not count a node of the local platform as a failure
                         (no attestation verifies such a node)
  --help                 print this text

exit status:
  0  every node passed
  1  at least one node failed
  2  there is no result: the arguments, a file, the network, the HTTP status or the response
";

/// What the command line asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `--help`.
    Help,
    Verify(Box<Arguments>),
}

/// The arguments of a verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arguments {
    pub source: Source,
    pub expected: Expected,
    /// `--allow-local`.
    pub allow_local: bool,
}

/// Where the attestation documents come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--url`: the attestation route of the running service. `url` has no trailing slash.
    Service { url: String },
    /// `--document` with `--nonce`: one stored Nitro attestation document.
    Document { path: String, nonce: Vec<u8> },
}

/// Where the expected measurements come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// No expected measurements: nothing is compared.
    Nothing,
    /// `--measurements`: the path of a `measurements.json`.
    File(String),
    /// `--pcr0`, `--pcr1` and `--pcr2`.
    Values([[u8; 48]; 3]),
}

/// The measurements a node is expected to attest: PCR0, PCR1 and PCR2 of a build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurements {
    /// The release the values belong to, when they come from a `measurements.json`.
    pub release: Option<String>,
    /// Where the values come from, as the report names it: the path of the file, or the
    /// arguments.
    pub origin: String,
    pub pcrs: [[u8; 48]; 3],
}

impl Measurements {
    /// The values of `--pcr0`, `--pcr1` and `--pcr2`.
    pub fn of_command_line(pcrs: [[u8; 48]; 3]) -> Measurements {
        Measurements {
            release: None,
            origin: "--pcr0, --pcr1 and --pcr2".to_string(),
            pcrs,
        }
    }

    /// Reads a `measurements.json`: a JSON object with the texts `release`, `pcr0`, `pcr1` and
    /// `pcr2`, the three PCRs as 96 lowercase hex characters. Other members are not read.
    /// `path` names the file in the report and in the error.
    pub fn of_file(path: &str, content: &[u8]) -> Result<Measurements, String> {
        let value: Value =
            serde_json::from_slice(content).map_err(|_| format!("{path} is not JSON"))?;
        let text = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path} has no text \"{name}\""))
        };
        let release = text("release")?;
        let mut pcrs = [[0u8; 48]; 3];
        for (index, slot) in pcrs.iter_mut().enumerate() {
            let name = format!("pcr{index}");
            *slot = pcr(&format!("\"{name}\" of {path}"), text(&name)?)?;
        }
        Ok(Measurements {
            release: Some(release.to_string()),
            origin: path.to_string(),
            pcrs,
        })
    }
}

/// Reads the command line (without the program name).
pub fn parse(arguments: &[String]) -> Result<Command, String> {
    let mut url = None;
    let mut document = None;
    let mut nonce = None;
    let mut measurements = None;
    let mut pcrs: [Option<String>; 3] = [None, None, None];
    let mut allow_local = false;

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        // `--name value` and `--name=value` are the same.
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (argument.as_str(), None),
        };
        let slot = match name {
            "--help" | "-h" | "--allow-local" => {
                if inline.is_some() {
                    return Err(format!("{name} takes no value"));
                }
                if name == "--allow-local" {
                    allow_local = true;
                    continue;
                }
                return Ok(Command::Help);
            }
            "--url" => &mut url,
            "--document" => &mut document,
            "--nonce" => &mut nonce,
            "--measurements" => &mut measurements,
            "--pcr0" => &mut pcrs[0],
            "--pcr1" => &mut pcrs[1],
            "--pcr2" => &mut pcrs[2],
            _ => return Err(format!("the argument {argument} is not known")),
        };
        let value = match inline {
            Some(value) => value,
            None => rest
                .next()
                .ok_or_else(|| format!("{name} needs a value"))?
                .as_str(),
        };
        if slot.replace(value.to_string()).is_some() {
            return Err(format!("{name} is given twice"));
        }
    }

    let expected =
        match (measurements, pcrs) {
            (Some(_), pcrs) if pcrs.iter().any(Option::is_some) => return Err(
                "--measurements and --pcr0, --pcr1, --pcr2 both give the expected measurements: \
                 give one of the two"
                    .to_string(),
            ),
            (Some(path), _) => Expected::File(path),
            (None, [None, None, None]) => Expected::Nothing,
            (None, [Some(pcr0), Some(pcr1), Some(pcr2)]) => Expected::Values([
                pcr("--pcr0", &pcr0)?,
                pcr("--pcr1", &pcr1)?,
                pcr("--pcr2", &pcr2)?,
            ]),
            (None, _) => return Err("--pcr0, --pcr1 and --pcr2 go together: give all three".into()),
        };

    let source = match (url, document) {
        (Some(_), Some(_)) => {
            return Err("--url and --document both say what is verified: give one".into())
        }
        (None, None) => return Err("give --url or --document".into()),
        (Some(url), None) => {
            if nonce.is_some() {
                return Err(
                    "--nonce goes with --document: the nonce of a request to --url is drawn at \
                     random"
                        .to_string(),
                );
            }
            Source::Service {
                url: service_url(&url)?,
            }
        }
        (None, Some(path)) => {
            if allow_local {
                return Err("--allow-local goes with --url".into());
            }
            let nonce = nonce.ok_or(
                "--document needs --nonce: the nonce the document was requested with, in hex",
            )?;
            let nonce = hex_decode(&nonce)
                .filter(|bytes| !bytes.is_empty())
                .ok_or("--nonce is not lowercase hex")?;
            Source::Document { path, nonce }
        }
    };

    Ok(Command::Verify(Box::new(Arguments {
        source,
        expected,
        allow_local,
    })))
}

/// The address of `--url` without trailing slashes: `https://` or `http://`, a host, and no
/// query and no fragment (the tool appends the route and the nonce).
fn service_url(text: &str) -> Result<String, String> {
    let host = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    match host {
        Some(host)
            if !host.is_empty()
                && !host.starts_with('/')
                && !text.contains(['?', '#'])
                && !text.contains(|character: char| {
                    character.is_whitespace() || character.is_control()
                }) =>
        {
            Ok(text.trim_end_matches('/').to_string())
        }
        _ => Err(
            "--url is an address of the form https://{host}, without a query and a fragment"
                .to_string(),
        ),
    }
}

/// A PCR value: 96 lowercase hex characters. `name` names the value in the error.
fn pcr(name: &str, text: &str) -> Result<[u8; 48], String> {
    hex_decode(text)
        .and_then(|bytes| <[u8; 48]>::try_from(bytes).ok())
        .ok_or_else(|| format!("{name} is not 96 lowercase hex characters"))
}

/// The bytes of lowercase hex. `None` for anything else.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    fn digit(character: u8) -> Option<u8> {
        match character {
            b'0'..=b'9' => Some(character - b'0'),
            b'a'..=b'f' => Some(character - b'a' + 10),
            _ => None,
        }
    }
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Lowercase hex of bytes.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `measurements.json` of the GitHub release v1.0.0 of this repository.
    const RELEASE_MEASUREMENTS: &[u8] =
        include_bytes!("../tests/fixtures/measurements-prerelease.json");
    const PCR0: &str = "d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7";
    const PCR1: &str = "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493";
    const PCR2: &str = "a20b4116edfa4777b9a128025b2c77fd3bfa41e2aedf7710ed6e6b03eebf1110f99e486772ffb0e6a7b8c37070d814f8";

    fn parse_words(words: &[&str]) -> Result<Command, String> {
        let arguments: Vec<String> = words.iter().map(|word| word.to_string()).collect();
        parse(&arguments)
    }

    fn verify(words: &[&str]) -> Arguments {
        match parse_words(words) {
            Ok(Command::Verify(arguments)) => *arguments,
            other => panic!("{other:?}"),
        }
    }

    fn pcr_bytes(text: &str) -> [u8; 48] {
        hex_decode(text).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_service_with_a_measurements_file() {
        assert_eq!(
            verify(&[
                "--url",
                "https://api.example.com",
                "--measurements",
                "out/measurements.json"
            ]),
            Arguments {
                source: Source::Service {
                    url: "https://api.example.com".to_string()
                },
                expected: Expected::File("out/measurements.json".to_string()),
                allow_local: false,
            }
        );
        // `--name=value`, a trailing slash, a path in front of the route, `--allow-local`.
        assert_eq!(
            verify(&[
                "--allow-local",
                "--measurements=m.json",
                "--url=http://127.0.0.1:8000/stack/"
            ]),
            Arguments {
                source: Source::Service {
                    url: "http://127.0.0.1:8000/stack".to_string()
                },
                expected: Expected::File("m.json".to_string()),
                allow_local: true,
            }
        );
    }

    #[test]
    fn the_service_with_three_values_and_with_nothing() {
        assert_eq!(
            verify(&[
                "--url",
                "https://api.example.com",
                "--pcr0",
                PCR0,
                "--pcr1",
                PCR1,
                "--pcr2",
                PCR2
            ])
            .expected,
            Expected::Values([pcr_bytes(PCR0), pcr_bytes(PCR1), pcr_bytes(PCR2)])
        );
        assert_eq!(
            verify(&["--url", "https://api.example.com"]).expected,
            Expected::Nothing
        );
    }

    #[test]
    fn a_stored_document_with_its_nonce() {
        assert_eq!(
            verify(&["--document", "document.cbor", "--nonce", "00ff10"]),
            Arguments {
                source: Source::Document {
                    path: "document.cbor".to_string(),
                    nonce: vec![0x00, 0xff, 0x10],
                },
                expected: Expected::Nothing,
                allow_local: false,
            }
        );
    }

    #[test]
    fn help() {
        assert_eq!(parse_words(&["--help"]), Ok(Command::Help));
        assert_eq!(parse_words(&["-h"]), Ok(Command::Help));
    }

    #[test]
    fn arguments_that_are_not_understood_are_refused() {
        let url = ["--url", "https://api.example.com"];
        let with = |more: &[&str]| parse_words(&[&url[..], more].concat());
        for words in [
            // No source, two sources.
            &[][..],
            &["--measurements", "m.json"],
            &[
                "--url",
                "https://a.example",
                "--document",
                "d.cbor",
                "--nonce",
                "00",
            ],
            // A stored document without its nonce, with a nonce that is not hex, with a flag
            // of the service.
            &["--document", "d.cbor"],
            &["--document", "d.cbor", "--nonce", ""],
            &["--document", "d.cbor", "--nonce", "0"],
            &["--document", "d.cbor", "--nonce", "0G"],
            &["--document", "d.cbor", "--nonce", "AB"],
            &["--document", "d.cbor", "--nonce", "00", "--allow-local"],
            // An address that is not one.
            &["--url", "api.example.com"],
            &["--url", "ftp://api.example.com"],
            &["--url", "https://"],
            &["--url", "https:///path"],
            &["--url", "https://api.example.com/?nonce=1"],
            &["--url", "https://api.example.com/#top"],
            &["--url", "https://api.example.com/a b"],
            // A value that is missing, an argument twice, an unknown argument, a word.
            &["--url"],
            &["--url", "https://a.example", "--url", "https://b.example"],
            &["--url", "https://a.example", "--verbose"],
            &["--url", "https://a.example", "extra"],
            &["--url", "https://a.example", "--allow-local=yes"],
            &["--help=yes"],
        ] {
            assert!(parse_words(words).is_err(), "{words:?}");
        }
        // A nonce for the service, one or two of the three values, both ways to give them, a
        // value that is not 96 lowercase hex characters.
        assert!(with(&["--nonce", "00"]).is_err());
        assert!(with(&["--pcr0", PCR0]).is_err());
        assert!(with(&["--pcr0", PCR0, "--pcr2", PCR2]).is_err());
        assert!(with(&["--measurements", "m.json", "--pcr0", PCR0]).is_err());
        let upper = PCR1.to_uppercase();
        for bad in [&PCR1[..94], "", upper.as_str(), &format!("{PCR1}00")] {
            assert!(
                with(&["--pcr0", PCR0, "--pcr1", bad, "--pcr2", PCR2]).is_err(),
                "{bad}"
            );
        }
        assert!(with(&["--pcr0", PCR0, "--pcr1", PCR1, "--pcr2", PCR2]).is_ok());
    }

    #[test]
    fn the_measurements_file_of_a_release_is_read() {
        assert_eq!(
            Measurements::of_file("out/measurements.json", RELEASE_MEASUREMENTS),
            Ok(Measurements {
                release: Some("v1.0.0".to_string()),
                origin: "out/measurements.json".to_string(),
                pcrs: [pcr_bytes(PCR0), pcr_bytes(PCR1), pcr_bytes(PCR2)],
            })
        );
    }

    #[test]
    fn a_file_that_is_not_a_measurements_file_is_refused() {
        let file = |pcr1: &str, release: &str| {
            format!(
                "{{\"release\":{release},\"pcr0\":\"{PCR0}\",\"pcr1\":{pcr1},\"pcr2\":\"{PCR2}\"}}"
            )
        };
        let read = |content: &str| Measurements::of_file("m.json", content.as_bytes());
        assert!(read(&file(&format!("\"{PCR1}\""), "\"dev\"")).is_ok());
        // No JSON, no object, a member that is missing, a release that is not a text, a PCR
        // that is not 96 lowercase hex characters.
        assert!(read("").is_err());
        assert!(read("[]").is_err());
        assert!(read(&format!("{{\"release\":\"dev\",\"pcr0\":\"{PCR0}\"}}")).is_err());
        assert!(read(&file(&format!("\"{PCR1}\""), "1")).is_err());
        assert!(read(&file("null", "\"dev\"")).is_err());
        assert!(read(&file(&format!("\"{}\"", &PCR1[..95]), "\"dev\"")).is_err());
        assert!(read(&file(&format!("\"{}\"", PCR1.to_uppercase()), "\"dev\"")).is_err());
        assert_eq!(
            read(&file("\"00\"", "\"dev\"")),
            Err("\"pcr1\" of m.json is not 96 lowercase hex characters".to_string())
        );
    }

    #[test]
    fn hex_is_lowercase_and_whole_bytes() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("FF"), None);
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("é"), None);
        assert_eq!(hex(&[0x00, 0xff, 0x10]), "00ff10");
    }
}
