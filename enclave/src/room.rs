//! The room a JSON text takes in memory once it is parsed (enclave.md section 8).
//!
//! A node parses JSON texts that others wrote: the body of a call, the meta of a frame, the
//! plaintext of a record (which the device of an account encrypted), the response of a token
//! address. What a parsed text holds is not a multiple of its length. A value of the parsed
//! form takes 72 bytes whatever it stands for, an array and an object keep their elements in
//! buffers of their own that grow by doubling, and a member of an object has a key and a
//! place in an index: the room of a parsed text grows with the number of its values.
//!
//! So a node does not bound what a parsed text holds by the length of the text. It counts
//! what decides it, in one pass over the bytes and before it parses them ([`Marks`]): the
//! arrays and objects of the text, and its commas. From those counts it computes a bound of
//! what the parsed value holds ([`Marks::value_room`]) and the share of the body budget a
//! call holds for its request ([`Marks::request_share`]).
//!
//! The constants are bounds for the parser of this program (`serde_json` with the map that
//! keeps the order of its keys) on a machine of 64 bits:
//!
//! - an array or an object that holds anything has a buffer for its first elements: four
//!   values of 72 bytes for an array, and for an object three members of 104 bytes (the hash
//!   of the key, the key, the value), an index, and the text of the first key as an
//!   allocation of its own. [`CONTAINER_BYTES`] covers the larger of the two;
//! - every further element follows a comma. A buffer has just doubled when it holds one
//!   element more than half its room, and while it grows the old buffer and the new one
//!   exist together: three times the room of the elements for a moment. That is 216 bytes
//!   for an element of an array, and 333 bytes for a member of an object with its part of
//!   the index, beside the allocations of its key and of a string value. [`COMMA_BYTES`]
//!   covers the larger of the two;
//! - a string holds its bytes, in an allocation that is up to a quarter larger than what it
//!   holds (the allocator of the node gives out slots of fixed sizes).
//!
//! The node program forbids unsafe code, so no test of this crate counts allocations. The
//! tests below compare the bound with what the parsed values state of their own room, and
//! the bound was compared with the allocations of the parser outside this repository.

/// The room an array or an object takes beside the room of its elements after the first: the
/// buffer of its first elements, the index of an object, and the first key.
pub const CONTAINER_BYTES: usize = 512;

/// The room one further element of an array or member of an object takes beside the bytes of
/// its strings: its place in the buffer of its container at the moment that buffer grows,
/// its part of the index of an object, and the allocations of its key and of its value.
pub const COMMA_BYTES: usize = 448;

/// The room of a parsed value beside its strings, its containers and their elements: the
/// value itself and the state of the parser.
const BASE_BYTES: usize = 1024;

/// How often a call holds the bytes of its request, at the most ([`Marks::request_share`]).
const REQUEST_TEXT_COPIES: usize = 10;

/// How often a call holds the room of the structure of its request, at the most
/// ([`Marks::request_share`]).
const REQUEST_STRUCTURE_COPIES: usize = 4;

/// What decides the room of a JSON text in memory: its length, its arrays and objects, and
/// its commas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    /// The bytes of the text.
    pub bytes: usize,
    /// The arrays and objects of the text: every `[` and `{` outside its strings.
    pub containers: usize,
    /// The commas of the text outside its strings: one in front of every element of an array
    /// and every member of an object but the first.
    pub commas: usize,
}

impl Marks {
    /// Counts the marks of `text` in one pass, without a copy and without parsing it.
    ///
    /// A string begins and ends with a quotation mark, and inside a string a backslash takes
    /// the byte behind it with it: the two rules by which the parser finds the end of a
    /// string. So on a JSON text the counts are those of its structure. On bytes that are no
    /// JSON text the parser stops at the first byte it cannot read, having made values of
    /// the text in front of that byte only, and the counts of the whole text are not below
    /// the counts of that part.
    pub fn of(text: &[u8]) -> Marks {
        let mut marks = Marks {
            bytes: text.len(),
            ..Marks::default()
        };
        let mut in_string = false;
        let mut escaped = false;
        for byte in text {
            if in_string {
                match (escaped, byte) {
                    (true, _) => escaped = false,
                    (false, b'\\') => escaped = true,
                    (false, b'"') => in_string = false,
                    (false, _) => {}
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => marks.containers = marks.containers.saturating_add(1),
                b',' => marks.commas = marks.commas.saturating_add(1),
                _ => {}
            }
        }
        marks
    }

    /// The room of the structure of the text: its containers and their elements.
    const fn structure_room(self) -> usize {
        self.containers
            .saturating_mul(CONTAINER_BYTES)
            .saturating_add(self.commas.saturating_mul(COMMA_BYTES))
    }

    /// A bound of the memory the parsed value of the text holds: the bytes of its strings
    /// (no more than the bytes of the text, and a quarter more for the allocations that hold
    /// them), and the room of its structure.
    ///
    /// While the text is parsed, the parser holds the text of a string that has an escape
    /// once more, in a buffer that grows by doubling: up to three times the bytes of the
    /// text beside this bound, for that time.
    pub const fn value_room(self) -> usize {
        self.bytes
            .saturating_add(self.bytes / 4)
            .saturating_add(self.structure_room())
            .saturating_add(BASE_BYTES)
    }

    /// The share of the body budget of the node a call holds for a request with these marks
    /// (the JSON body of a call, the meta of a frame), from before the request is parsed to
    /// the end of the call: a bound of the parsed request and of what the call makes of it.
    ///
    /// - The bytes of the request, [`REQUEST_TEXT_COPIES`] times. A string of the request
    ///   stands in the parsed request, and a call copies it a bounded number of times. The
    ///   address and the headers of a request to a provider are the strings a call holds
    ///   most often: in the request the node assembles, in the request of the HTTP client,
    ///   in the event of the request (the address), and in the head the HTTP client writes,
    ///   whose buffer grows by doubling. The text of a record stands in the record a call
    ///   reads from its request, and in its ciphertext and its plaintext while the record is
    ///   opened. While the request is parsed, before any of these copies exists, the same
    ///   bytes cover the body the call read and the buffer of the parser.
    /// - The room of the structure of the request, [`REQUEST_STRUCTURE_COPIES`] times: the
    ///   parsed request, and for every header and every request of a batch the entries of
    ///   the lists and maps a call makes of them (the request the node assembles, the request
    ///   and the header map of the HTTP client, the event of a request and its copy for the
    ///   log).
    pub const fn request_share(self) -> usize {
        self.bytes
            .saturating_mul(REQUEST_TEXT_COPIES)
            .saturating_add(
                self.structure_room()
                    .saturating_mul(REQUEST_STRUCTURE_COPIES),
            )
            .saturating_add(BASE_BYTES * REQUEST_STRUCTURE_COPIES)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn marks(text: &str) -> (usize, usize) {
        let marks = Marks::of(text.as_bytes());
        assert_eq!(marks.bytes, text.len());
        (marks.containers, marks.commas)
    }

    #[test]
    fn the_marks_of_a_text_are_its_containers_and_its_commas_outside_strings() {
        assert_eq!(marks(""), (0, 0));
        assert_eq!(marks("7"), (0, 0));
        assert_eq!(marks("\"text\""), (0, 0));
        assert_eq!(marks("[]"), (1, 0));
        assert_eq!(marks("{}"), (1, 0));
        assert_eq!(marks("[1,2,3]"), (1, 2));
        assert_eq!(marks("{\"a\":1,\"b\":[true,null],\"c\":{}}"), (3, 3));
        // The marks inside a string are bytes of that string.
        assert_eq!(marks("\"[{,,}]\""), (0, 0));
        assert_eq!(marks("[\"a,b\",\"[\",\"{\"]"), (1, 2));
        // An escaped quotation mark does not end its string, and an escaped backslash does
        // not escape the quotation mark behind it.
        assert_eq!(marks("[\"a\\\",[\",1]"), (1, 1));
        assert_eq!(marks("[\"a\\\\\",[1],2]"), (2, 2));
        assert_eq!(marks("[\"\\\\\\\"\",{}]"), (2, 1));
        // An escape of four hexadecimal digits is bytes of its string.
        assert_eq!(marks("[\"\\u005b\\u002c\",0]"), (1, 1));
        // White space between the values changes nothing.
        assert_eq!(marks(" [ 1 , [ 2 ] ,\n{ \"k\" : 3 } ] "), (3, 2));
        // Bytes that are no JSON text: the marks are counted all the same.
        assert_eq!(marks("[[[,,"), (3, 2));
        assert_eq!(marks("]},"), (0, 1));
    }

    #[test]
    fn the_room_of_a_text_is_its_bytes_and_the_room_of_its_structure() {
        let marks = Marks {
            bytes: 1000,
            containers: 3,
            commas: 5,
        };
        // 1,000 bytes and a quarter, three containers of 512 bytes, five commas of 448
        // bytes, and 1,024 bytes.
        assert_eq!(marks.value_room(), 1000 + 250 + 1536 + 2240 + 1024);
        // Ten times the bytes, four times the room of the structure and of the base.
        assert_eq!(marks.request_share(), 10_000 + 4 * (1536 + 2240) + 4096);
        // A text without a value.
        assert_eq!(Marks::of(b"").value_room(), 1024);
        assert_eq!(Marks::of(b"").request_share(), 4096);
        // The request of a `forward` call for a record of 2,184 characters with four headers:
        // one object for the meta, one for the record, one array for the headers and one for
        // each header.
        let meta = serde_json::json!({
            "user_id": "u_01HZX3C9R7A1B2C3D4E5F6G7H8",
            "record": {"v": 1, "id": "A".repeat(22), "user_id": "u_01HZX3C9R7A1B2C3D4E5F6G7H8",
                "key_id": "0123456789abcdef", "custody": "enclave", "kind": "oauth",
                "provider": "google_workspace", "nonce": "B".repeat(16), "ct": "C".repeat(2184)},
            "method": "GET",
            "url": "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=50",
            "headers": [["accept", "application/json"], ["x-a", "1"], ["x-b", "2"], ["x-c", "3"]],
            "context": "tool:gmail.search",
            "timeout_ms": 30000,
        });
        let text = serde_json::to_vec(&meta).unwrap();
        let marks = Marks::of(&text);
        assert_eq!((marks.containers, marks.commas), (7, 21));
        assert_eq!(
            marks.request_share(),
            10 * text.len() + 4 * (7 * 512 + 21 * 448) + 4096
        );
        assert!(
            marks.request_share() < 90 * 1024,
            "{}",
            marks.request_share()
        );
        // The counts do not overflow.
        let most = Marks {
            bytes: usize::MAX,
            containers: usize::MAX,
            commas: usize::MAX,
        };
        assert_eq!(most.value_room(), usize::MAX);
        assert_eq!(most.request_share(), usize::MAX);
    }

    /// What a parsed value states of its own room: for every value 72 bytes in the buffer of
    /// its container (the room of that buffer for an array, which says it; a member of an
    /// object with its hash and its key), and the bytes of its strings. It is below what the
    /// value holds: the room of the buffer of an object, its index and what an allocator
    /// adds are not in it.
    fn stated_room(value: &Value) -> usize {
        const VALUE: usize = std::mem::size_of::<Value>();
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
            Value::String(text) => text.capacity(),
            Value::Array(elements) => {
                elements.capacity() * VALUE + elements.iter().map(stated_room).sum::<usize>()
            }
            Value::Object(members) => members
                .iter()
                .map(|(key, member)| VALUE + 32 + key.capacity() + stated_room(member))
                .sum(),
        }
    }

    /// `unit` between `[` and `]`, as often as `bytes` bytes hold it.
    fn repeated(unit: &str, bytes: usize) -> String {
        let count = (bytes - 2) / (unit.len() + 1);
        format!("[{}]", vec![unit; count.max(1)].join(","))
    }

    #[test]
    fn the_room_of_a_text_is_not_below_what_its_parsed_value_states() {
        assert_eq!(std::mem::size_of::<Value>(), 72);
        let mut texts: Vec<String> = vec![
            "0".into(),
            "\"a string\"".into(),
            "[]".into(),
            "{}".into(),
            "[0]".into(),
            "{\"a\":0}".into(),
        ];
        // Texts of many values, of many containers, and of containers that hold one another.
        for unit in [
            "0",
            "\"\"",
            "\"a\"",
            "[]",
            "{}",
            "[0]",
            "[[]]",
            "[0,0]",
            "[0,0,0,0,0]",
            "{\"a\":0}",
            "{\"\":0}",
            "{\"a\":[0]}",
            "{\"a\":0,\"b\":0}",
            "[\"a\",\"b\"]",
            "[[[[[[[[0]]]]]]]]",
            "{\"a\":{\"a\":{\"a\":{\"a\":0}}}}",
        ] {
            for bytes in [64, 4096, 65_536] {
                texts.push(repeated(unit, bytes));
            }
        }
        // Arrays and objects of every size around the sizes at which a buffer grows.
        for count in (1..=40).chain([63, 64, 65, 127, 128, 129, 1023, 1024, 1025]) {
            texts.push(format!("[{}]", vec!["0"; count].join(",")));
            let members: Vec<String> = (0..count).map(|index| format!("\"{index}\":0")).collect();
            texts.push(format!("{{{}}}", members.join(",")));
            let members: Vec<String> = (0..count)
                .map(|index| format!("\"{index}\":\"v\""))
                .collect();
            texts.push(format!("{{{}}}", members.join(",")));
        }
        for text in texts {
            let value: Value = serde_json::from_str(&text).unwrap();
            let marks = Marks::of(text.as_bytes());
            let head: String = text.chars().take(40).collect();
            assert!(
                stated_room(&value) + std::mem::size_of::<Value>() <= marks.value_room(),
                "{} bytes of {head}: {} above {}",
                text.len(),
                stated_room(&value),
                marks.value_room()
            );
            // A call holds its parsed request within the share of that request.
            assert!(marks.value_room() <= marks.request_share());
        }
    }

    #[test]
    fn the_room_of_a_text_follows_its_values_and_not_its_length() {
        // Two texts of the same length. The room of the one that holds many values follows
        // the count of those values: it is above what the parsed value states of its own
        // room, which is many times the bytes of the text.
        let text = repeated("[[0]]", 65_536);
        let value: Value = serde_json::from_str(&text).unwrap();
        let marks = Marks::of(text.as_bytes());
        assert!(stated_room(&value) > 10 * text.len());
        assert!(marks.value_room() > stated_room(&value));
        // The same number of bytes in one string: the room is the bytes and a quarter.
        let one = format!("\"{}\"", "s".repeat(65_534));
        let marks = Marks::of(one.as_bytes());
        assert_eq!(marks.value_room(), 65_536 + 16_384 + 1024);
    }
}
