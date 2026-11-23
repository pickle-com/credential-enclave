//! The frame of `POST /v1/forward` (enclave.md 5.8), used for the request body and for the
//! response body:
//!
//! ```text
//! frame = meta_len (unsigned 32 bit, big-endian) || meta (UTF-8 JSON, meta_len bytes) || payload
//! ```
//!
//! And the stream, the response body of a `forward` call that asked for one: the head of a
//! frame, then the body of the provider in parts while it arrives, then an end record.
//!
//! ```text
//! stream = meta_len (unsigned 32 bit, big-endian) || meta (UTF-8 JSON, meta_len bytes) || part* || end
//! part   = part_len (unsigned 32 bit, big-endian, at least 1) || part_len bytes of the body
//! end    = 0 (unsigned 32 bit) || end record (UTF-8 JSON, all the rest)
//! ```

use credential_enclave_protocol::encoding::to_json;
use credential_enclave_protocol::ProtocolError;
use hyper::body::Bytes;
use serde::Serialize;

/// The content type of a frame.
pub const CONTENT_TYPE: &str = "application/vnd.pickle.frame";

/// The content type of a stream.
pub const STREAM_CONTENT_TYPE: &str = "application/vnd.pickle.stream";

/// The most bytes of one part of a stream: a part is a length of four bytes and its bytes.
pub const STREAM_PART_LIMIT_BYTES: usize = 1024 * 1024;

/// The length prefix of one part of a stream. `None` for a part of no byte (the prefix 0 is
/// the mark of the end record) and for a part above [`STREAM_PART_LIMIT_BYTES`].
pub fn stream_part_prefix(part: &[u8]) -> Option<[u8; 4]> {
    if part.is_empty() || part.len() > STREAM_PART_LIMIT_BYTES {
        return None;
    }
    u32::try_from(part.len()).ok().map(u32::to_be_bytes)
}

/// The end of a stream: the mark of the end and the end record.
pub fn encode_stream_end<T: Serialize>(record: &T) -> Vec<u8> {
    let record = to_json(record);
    let mut end = Vec::with_capacity(4 + record.len());
    end.extend_from_slice(&0u32.to_be_bytes());
    end.extend_from_slice(&record);
    end
}

/// Longest `meta` a node reads: 1 MiB. A request meta holds one record, one address and the
/// request headers.
pub const META_LIMIT_BYTES: usize = 1024 * 1024;

/// The length prefix and the meta of a frame. The payload follows these bytes.
pub fn encode_head<T: Serialize>(meta: &T) -> Vec<u8> {
    let meta = to_json(meta);
    // The meta of a response is its head, which has the bound of the HTTP connection it
    // arrived on, far below 4 GiB. A length the prefix cannot state would be written as the
    // largest one, which every reader refuses (`META_LIMIT_BYTES`).
    let length = u32::try_from(meta.len()).unwrap_or(u32::MAX);
    let mut head = Vec::with_capacity(4 + meta.len());
    head.extend_from_slice(&length.to_be_bytes());
    head.extend_from_slice(&meta);
    head
}

/// Splits a frame into its meta (a JSON object) and its payload. A frame shorter than its
/// length prefix says, a meta above [`META_LIMIT_BYTES`] and a meta that is not a JSON object
/// are `invalid_request`.
pub fn decode(frame: &Bytes) -> Result<(serde_json::Value, Bytes), ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ProtocolError::InvalidRequest)?;
    let meta_length = u32::from_be_bytes(prefix) as usize;
    if meta_length > META_LIMIT_BYTES {
        return Err(ProtocolError::InvalidRequest);
    }
    // The meta lies in the frame whole, behind the four bytes of its length.
    let payload_at = 4 + meta_length;
    let meta = frame
        .get(4..payload_at)
        .ok_or(ProtocolError::InvalidRequest)?;
    let meta: serde_json::Value =
        serde_json::from_slice(meta).map_err(|_| ProtocolError::InvalidRequest)?;
    if !meta.is_object() {
        return Err(ProtocolError::InvalidRequest);
    }
    // `payload_at` is not behind the end of the frame: the meta was read up to it.
    Ok((meta, frame.slice(payload_at..)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(meta: &[u8], payload: &[u8]) -> Bytes {
        let mut bytes = (meta.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(meta);
        bytes.extend_from_slice(payload);
        Bytes::from(bytes)
    }

    #[test]
    fn a_frame_round_trips() {
        let mut bytes =
            encode_head(&json!({"status": 200, "headers": [["a", "b"]], "entry": null}));
        assert_eq!(bytes[..4], ((bytes.len() - 4) as u32).to_be_bytes());
        assert_eq!(
            &bytes[4..],
            b"{\"status\":200,\"headers\":[[\"a\",\"b\"]],\"entry\":null}"
        );
        bytes.extend_from_slice(b"\x00\x01payload");
        let (meta, payload) = decode(&Bytes::from(bytes)).unwrap();
        assert_eq!(meta["status"], 200);
        assert_eq!(payload.as_ref(), b"\x00\x01payload");
    }

    #[test]
    fn an_empty_payload_is_a_valid_frame() {
        let (meta, payload) = decode(&frame(b"{}", b"")).unwrap();
        assert!(meta.as_object().unwrap().is_empty());
        assert!(payload.is_empty());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let invalid = Err(ProtocolError::InvalidRequest);
        assert_eq!(decode(&Bytes::from_static(b"")).map(|_| ()), invalid);
        assert_eq!(
            decode(&Bytes::from_static(b"\x00\x00\x00")).map(|_| ()),
            invalid
        );
        // The length prefix points past the end.
        assert_eq!(
            decode(&Bytes::from_static(b"\x00\x00\x00\x05{}")).map(|_| ()),
            invalid
        );
        // The meta is not JSON, or not an object.
        assert_eq!(decode(&frame(b"nope", b"")).map(|_| ()), invalid);
        assert_eq!(decode(&frame(b"[1]", b"")).map(|_| ()), invalid);
        // A meta above the limit.
        let mut large = ((META_LIMIT_BYTES + 1) as u32).to_be_bytes().to_vec();
        large.resize(4 + META_LIMIT_BYTES + 1, b' ');
        assert_eq!(decode(&Bytes::from(large)).map(|_| ()), invalid);
    }
}
