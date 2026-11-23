//! The reader of the responses of an IMAP server (RFC 3501), as far as a node reads them.
//!
//! A mail server answers with bytes the node does not choose, and inside them stand texts the
//! sender of a message chose (a subject, an address) and names the owner of a mailbox chose.
//! This module is the one place that reads those bytes. It reads the responses to the commands
//! a mail call sends (`LOGIN`, `LIST`, `EXAMINE`, `UID SEARCH`, `UID FETCH`) and takes from a
//! response what those commands need: the condition of a status response with its response
//! code, the name of a folder, the numbers of a search, and of a message its UID, its size, its
//! header and its body. Every other part of a response is passed over by its syntax and is not
//! interpreted.
//!
//! Two parts, neither of which performs input or output:
//!
//! - [`Reader`] finds the end of a response in the bytes of a connection. A response is one
//!   line, or a line that declares a literal (`{N}` in front of its line end), the `N` octets
//!   of that literal, and the line that follows them, which can declare a further literal. The
//!   reader reports a declaration before it takes an octet of the literal, so whoever feeds it
//!   holds the length against a bound first. It is the one place that says where the octets of
//!   a literal are: what it hands on as a response is what [`parse`] reads.
//! - [`parse`] reads one response.
//!
//! No input makes a function of this module fail in another way than by its return value. The
//! module indexes nothing without a check, follows a list inside a list by a count and not by
//! a call, and allocates only for bytes it was handed.

/// The longest declaration of a literal the reader reads: the digits of an unsigned number of
/// 64 bits.
const LITERAL_DIGITS: usize = 20;

/// One response as [`Reader`] hands it on: the text of its lines without their line ends and
/// without the declarations of its literals, and the literals with the place of each in that
/// text.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Raw {
    text: Vec<u8>,
    /// The place in `text` at which each literal stands, in the order of the literals.
    marks: Vec<usize>,
    literals: Vec<Vec<u8>>,
}

/// What [`Reader::feed`] found in the bytes it took.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The bytes end inside a response: the reader took all of them and needs more.
    More,
    /// A line declared a literal of this many octets. The reader takes no further byte until
    /// the literal is admitted ([`Reader::admit`]).
    Literal(u64),
    /// A whole response.
    Response(Raw),
    /// A declaration of a literal whose digits are no unsigned number of 64 bits.
    Malformed,
}

/// Where the reader stands in a response.
#[derive(Debug, PartialEq, Eq)]
enum Place {
    /// In a line.
    Line,
    /// Behind the declaration of a literal that was not admitted yet.
    Declared(u64),
    /// In the octets of a literal: those still to come.
    Octets(u64),
}

/// Finds the responses in the bytes of a connection ([`Reader::feed`]).
///
/// A line ends with LF, and a CR in front of it belongs to the line end. A line that ends in
/// `{N}` declares a literal when its response can hold one: an untagged response that is no
/// status response. The text of a status response (`OK`, `NO`, `BAD`, `BYE`, `PREAUTH`, with
/// a tag or without) and of a continuation request reaches to the end of its line (RFC 3501
/// section 7.1: `resp-text`), braces included. A server can put a text of the caller there
/// (the name in a refused `LOGIN`, the name of a folder that does not exist), so such a
/// response is one line whatever stands at its end.
#[derive(Debug)]
pub(crate) struct Reader {
    response: Raw,
    /// The length of `response.text` at the start of the line the reader stands in.
    line_from: usize,
    place: Place,
    /// Whether the response the reader stands in can hold literals. Decided at the end of its
    /// first line.
    literals: bool,
    /// True while the reader stands in the first line of a response.
    first_line: bool,
}

impl Default for Reader {
    fn default() -> Reader {
        Reader {
            response: Raw::default(),
            line_from: 0,
            place: Place::Line,
            literals: false,
            first_line: true,
        }
    }
}

impl Reader {
    /// True when the reader stands between two responses: it holds no byte of one.
    pub(crate) fn at_rest(&self) -> bool {
        self.place == Place::Line
            && self.first_line
            && self.response.text.is_empty()
            && self.response.marks.is_empty()
    }

    /// The bytes of text the reader holds of the response it stands in: its lines so far,
    /// without the octets of its literals. Whoever feeds the reader holds this against a
    /// bound: the reader takes the bytes of a line until the line ends.
    pub(crate) fn text_bytes(&self) -> usize {
        self.response.text.len()
    }

    /// Admits the literal the reader reported ([`Step::Literal`]): its octets are taken from
    /// the bytes that follow. The buffer of the literal is made here, with the length that
    /// was declared, so it is not moved while it fills. A length no buffer can have gets a
    /// buffer that grows with the octets that arrive.
    pub(crate) fn admit(&mut self) {
        if let Place::Declared(octets) = self.place {
            self.response.marks.push(self.response.text.len());
            let mut literal = Vec::new();
            if let Ok(octets) = usize::try_from(octets) {
                let _ = literal.try_reserve_exact(octets);
            }
            self.response.literals.push(literal);
            self.place = match octets {
                0 => Place::Line,
                octets => Place::Octets(octets),
            };
            self.line_from = self.response.text.len();
        }
    }

    /// Takes bytes from the front of `bytes` and returns how many it took and what it found.
    /// It takes no byte behind the end of a response and none behind a declaration.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> (usize, Step) {
        let mut taken = 0usize;
        loop {
            let rest = bytes.get(taken..).unwrap_or_default();
            match self.place {
                Place::Declared(octets) => return (taken, Step::Literal(octets)),
                Place::Octets(missing) => {
                    let count = usize::try_from(missing).map_or(rest.len(), |m| m.min(rest.len()));
                    let octets = rest.get(..count).unwrap_or_default();
                    if let Some(literal) = self.response.literals.last_mut() {
                        literal.extend_from_slice(octets);
                    }
                    taken = taken.saturating_add(octets.len());
                    match missing.saturating_sub(octets.len() as u64) {
                        0 => self.place = Place::Line,
                        missing => {
                            self.place = Place::Octets(missing);
                            return (taken, Step::More);
                        }
                    }
                }
                Place::Line => {
                    let Some(end) = memchr::memchr(b'\n', rest) else {
                        self.response.text.extend_from_slice(rest);
                        return (taken.saturating_add(rest.len()), Step::More);
                    };
                    self.response
                        .text
                        .extend_from_slice(rest.get(..end).unwrap_or_default());
                    taken = taken.saturating_add(end).saturating_add(1);
                    if self.response.text.len() > self.line_from
                        && self.response.text.last() == Some(&b'\r')
                    {
                        self.response.text.pop();
                    }
                    if self.first_line {
                        self.literals = holds_literals(&self.response.text);
                        self.first_line = false;
                    }
                    match self.declaration() {
                        Some(Ok(octets)) => self.place = Place::Declared(octets),
                        Some(Err(())) => {
                            *self = Reader::default();
                            return (taken, Step::Malformed);
                        }
                        None => {
                            let response = std::mem::take(&mut self.response);
                            *self = Reader::default();
                            return (taken, Step::Response(response));
                        }
                    }
                }
            }
        }
    }

    /// The declaration the line that just ended ends with, cut off the text: `{` digits `}`.
    /// `None` for a line without one and for a response that holds no literals, `Err` for
    /// digits that are no unsigned number of 64 bits.
    fn declaration(&mut self) -> Option<Result<u64, ()>> {
        if !self.literals {
            return None;
        }
        let line = self.response.text.get(self.line_from..)?;
        let inside = line.strip_suffix(b"}")?;
        let open = inside.iter().rposition(|byte| *byte == b'{')?;
        let digits = inside.get(open.saturating_add(1)..)?;
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let octets = match digits.len() <= LITERAL_DIGITS {
            true => std::str::from_utf8(digits)
                .ok()
                .and_then(|digits| digits.parse::<u64>().ok()),
            false => None,
        };
        let kept = self.line_from.saturating_add(open);
        self.response.text.truncate(kept);
        Some(octets.ok_or(()))
    }
}

/// True when the response whose first line is `line` can hold literals: an untagged response
/// that is no status response.
fn holds_literals(line: &[u8]) -> bool {
    let Some(behind) = line.strip_prefix(b"* ") else {
        return false;
    };
    let (word, _) = split_word(behind);
    Condition::of(word).is_none()
}

/// The condition of a status response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    Ok,
    No,
    Bad,
    Bye,
    Preauth,
}

impl Condition {
    fn of(word: &[u8]) -> Option<Condition> {
        [
            (&b"OK"[..], Condition::Ok),
            (b"NO", Condition::No),
            (b"BAD", Condition::Bad),
            (b"BYE", Condition::Bye),
            (b"PREAUTH", Condition::Preauth),
        ]
        .into_iter()
        .find(|(name, _)| word.eq_ignore_ascii_case(name))
        .map(|(_, condition)| condition)
    }
}

/// The response codes of a status response a node reads (RFC 3501 section 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    UidValidity(u32),
    UidNext(u32),
    /// No response code, or another one.
    Other,
}

/// A status response: its condition, the response code a node reads, and what stands behind
/// the condition (the response code and the text), as the server sent it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) condition: Condition,
    pub(crate) code: Code,
    behind: Vec<u8>,
}

impl Status {
    /// True when what stands behind the condition holds `word`, in any case of its ASCII
    /// letters. The bytes of the server are compared as bytes: no text is made of them.
    pub(crate) fn mentions(&self, word: &[u8]) -> bool {
        !word.is_empty()
            && self
                .behind
                .windows(word.len())
                .any(|window| window.eq_ignore_ascii_case(word))
    }
}

/// One message of a `FETCH` response: the items a node asks for.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Fetched {
    pub(crate) uid: Option<u32>,
    pub(crate) size: Option<u64>,
    pub(crate) header: Option<Vec<u8>>,
    pub(crate) body: Option<Vec<u8>>,
}

/// A response, as far as a node reads it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Response {
    /// A continuation request: the server asks for the octets of a literal of the command.
    Continue,
    /// The completion of the command with this tag.
    Tagged(Vec<u8>, Status),
    /// An untagged status response.
    Untagged(Status),
    /// The name of a folder (`LIST`).
    List(String),
    /// The numbers of a search (`SEARCH`).
    Search(Vec<u32>),
    /// One message (`FETCH`).
    Fetch(Fetched),
    /// Any other response: it is passed over.
    Other,
}

/// Reads a response. `None` for bytes that are no response: a line that begins with a blank,
/// a tag without a condition behind it, and a `LIST` or `FETCH` response in another form than
/// its syntax.
pub(crate) fn parse(mut raw: Raw) -> Option<Response> {
    let text = std::mem::take(&mut raw.text);
    if text.is_empty() && raw.marks.is_empty() {
        // An empty line says nothing.
        return Some(Response::Other);
    }
    if text.first() == Some(&b'+') {
        return Some(Response::Continue);
    }
    let (first, behind) = split_word(&text);
    if first.is_empty() {
        return None;
    }
    if first != b"*" {
        // A response with a tag is a status response.
        let (word, behind) = split_word(behind);
        return Some(Response::Tagged(
            first.to_vec(),
            status(Condition::of(word)?, behind),
        ));
    }
    let (word, behind_word) = split_word(behind);
    if let Some(condition) = Condition::of(word) {
        return Some(Response::Untagged(status(condition, behind_word)));
    }
    // The data of a response: what stands behind `* `.
    let mut cursor = Cursor {
        text: &text,
        at: text.len().saturating_sub(behind.len()),
        marks: &raw.marks,
        literal: 0,
    };
    let Some(Token::Atom(name)) = cursor.next(false) else {
        return Some(Response::Other);
    };
    if name.eq_ignore_ascii_case(b"LIST") {
        return list(&mut cursor, &mut raw.literals);
    }
    if name.eq_ignore_ascii_case(b"SEARCH") {
        return Some(Response::Search(search(&mut cursor)));
    }
    if number(name).is_some() {
        if let Some(Token::Atom(kind)) = cursor.next(false) {
            if kind.eq_ignore_ascii_case(b"FETCH") {
                return fetch(&mut cursor, &mut raw.literals).map(Response::Fetch);
            }
        }
    }
    Some(Response::Other)
}

/// The word at the front of `text` and what stands behind the space that ends it.
fn split_word(text: &[u8]) -> (&[u8], &[u8]) {
    match text.iter().position(|byte| *byte == b' ') {
        Some(space) => (
            text.get(..space).unwrap_or_default(),
            text.get(space.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (text, &[]),
    }
}

/// The status response with this condition whose line goes on with `behind`: an optional
/// response code in brackets, and a text.
fn status(condition: Condition, behind: &[u8]) -> Status {
    let code = behind
        .strip_prefix(b"[")
        .and_then(|inside| inside.split(|byte| *byte == b']').next())
        .map_or(Code::Other, |inside| {
            let (name, argument) = split_word(inside);
            match number(argument) {
                Some(value) if name.eq_ignore_ascii_case(b"UIDVALIDITY") => {
                    Code::UidValidity(value)
                }
                Some(value) if name.eq_ignore_ascii_case(b"UIDNEXT") => Code::UidNext(value),
                _ => Code::Other,
            }
        });
    Status {
        condition,
        code,
        behind: behind.to_vec(),
    }
}

/// A number of RFC 3501: digits that are an unsigned integer of 32 bits.
fn number(text: &[u8]) -> Option<u32> {
    wide_number(text).and_then(|value| u32::try_from(value).ok())
}

/// Digits that are an unsigned integer of 64 bits (RFC 9051: `number64`).
fn wide_number(text: &[u8]) -> Option<u64> {
    match !text.is_empty() && text.len() <= LITERAL_DIGITS && text.iter().all(u8::is_ascii_digit) {
        true => std::str::from_utf8(text).ok()?.parse().ok(),
        false => None,
    }
}

/// One token of the data of a response.
#[derive(Debug, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    /// An atom.
    Atom(&'a [u8]),
    /// A quoted string, without its quotes and its escapes.
    Quoted(Vec<u8>),
    /// The literal with this index.
    Literal(usize),
}

/// A place in the data of a response.
struct Cursor<'a> {
    /// The text of the response.
    text: &'a [u8],
    at: usize,
    /// The places of the literals in `text`.
    marks: &'a [usize],
    /// The index of the next literal.
    literal: usize,
}

impl<'a> Cursor<'a> {
    /// True when the next literal stands at the place the cursor has reached.
    fn at_literal(&self) -> bool {
        self.marks.get(self.literal) == Some(&self.at)
    }

    /// The next token. `None` at the end of the response, and for a quoted string that has no
    /// end or that a literal stands in.
    ///
    /// With `sections`, an atom reaches over what stands in brackets inside it: the name of a
    /// `FETCH` item names a section of a message (`BODY[HEADER.FIELDS (DATE FROM)]`).
    fn next(&mut self, sections: bool) -> Option<Token<'a>> {
        while !self.at_literal() && self.text.get(self.at) == Some(&b' ') {
            self.at = self.at.saturating_add(1);
        }
        if self.at_literal() {
            self.literal = self.literal.saturating_add(1);
            return Some(Token::Literal(self.literal.saturating_sub(1)));
        }
        match *self.text.get(self.at)? {
            b'(' => {
                self.at = self.at.saturating_add(1);
                Some(Token::Open)
            }
            b')' => {
                self.at = self.at.saturating_add(1);
                Some(Token::Close)
            }
            b'"' => {
                let mut quoted = Vec::new();
                self.at = self.at.saturating_add(1);
                loop {
                    if self.at_literal() {
                        return None;
                    }
                    match *self.text.get(self.at)? {
                        b'"' => break,
                        b'\\' => {
                            quoted.push(*self.text.get(self.at.saturating_add(1))?);
                            self.at = self.at.saturating_add(2);
                        }
                        byte => {
                            quoted.push(byte);
                            self.at = self.at.saturating_add(1);
                        }
                    }
                }
                self.at = self.at.saturating_add(1);
                Some(Token::Quoted(quoted))
            }
            _ => {
                let from = self.at;
                let mut bracketed = false;
                loop {
                    // A literal inside the brackets of a section is part of the name of the
                    // section: the atom goes on behind it.
                    while bracketed && self.at_literal() {
                        self.literal = self.literal.saturating_add(1);
                    }
                    let Some(byte) = self.text.get(self.at) else {
                        break;
                    };
                    let ends = matches!(byte, b' ' | b'(' | b')' | b'"')
                        || (self.at > from && self.at_literal());
                    if !bracketed && ends {
                        break;
                    }
                    match byte {
                        b'[' if sections => bracketed = true,
                        b']' => bracketed = false,
                        _ => {}
                    }
                    self.at = self.at.saturating_add(1);
                }
                Some(Token::Atom(self.text.get(from..self.at)?))
            }
        }
    }

    /// Passes over one value: a token, or a list with everything inside it. False at the end
    /// of the response. A list inside a list is followed by a count and not by a call, so no
    /// depth of lists costs more than its tokens.
    fn skip(&mut self) -> bool {
        let mut depth = 0u64;
        loop {
            match self.next(false) {
                None => return false,
                Some(Token::Open) => depth = depth.saturating_add(1),
                Some(Token::Close) => depth = depth.saturating_sub(1),
                Some(Token::Atom(_) | Token::Quoted(_) | Token::Literal(_)) => {}
            }
            if depth == 0 {
                return true;
            }
        }
    }
}

/// The bytes of a string token: a quoted string or a literal, which is taken out of
/// `literals`. `Ok(None)` for `NIL`, `Err` for any other token.
fn string(token: Token<'_>, literals: &mut [Vec<u8>]) -> Result<Option<Vec<u8>>, ()> {
    match token {
        Token::Quoted(bytes) => Ok(Some(bytes)),
        Token::Literal(index) => literals
            .get_mut(index)
            .map(std::mem::take)
            .map(Some)
            .ok_or(()),
        Token::Atom(atom) if atom.eq_ignore_ascii_case(b"NIL") => Ok(None),
        Token::Atom(_) | Token::Open | Token::Close => Err(()),
    }
}

/// The longest name of a folder a node hands on: the longest name a read takes.
pub(crate) const FOLDER_NAME_BYTES: usize = 1024;

/// `LIST (attributes) delimiter name`: the name of the folder. `None` for a response in
/// another form.
///
/// A node hands on the names it can put into a command: 1 to [`FOLDER_NAME_BYTES`] bytes of
/// UTF-8 without a control character. A folder with another name is passed over
/// ([`Response::Other`]). The name `INBOX` in any case of its letters is `INBOX` (RFC 3501
/// section 5.1).
fn list(cursor: &mut Cursor<'_>, literals: &mut [Vec<u8>]) -> Option<Response> {
    if cursor.next(false)? != Token::Open {
        return None;
    }
    let mut depth = 1u64;
    while depth > 0 {
        match cursor.next(false)? {
            Token::Open => depth = depth.saturating_add(1),
            Token::Close => depth = depth.saturating_sub(1),
            Token::Atom(_) | Token::Quoted(_) | Token::Literal(_) => {}
        }
    }
    // The delimiter: a quoted character, or `NIL`.
    if matches!(cursor.next(false)?, Token::Open | Token::Close) {
        return None;
    }
    let name = match cursor.next(false)? {
        Token::Atom(name) => name.to_vec(),
        token => string(token, literals).ok()??,
    };
    let Ok(name) = String::from_utf8(name) else {
        return Some(Response::Other);
    };
    if name.is_empty() || name.len() > FOLDER_NAME_BYTES || name.chars().any(char::is_control) {
        return Some(Response::Other);
    }
    Some(Response::List(match name.eq_ignore_ascii_case("INBOX") {
        true => "INBOX".to_string(),
        false => name,
    }))
}

/// `SEARCH number ...`: the numbers. What follows the numbers (the modification sequence of
/// an extension) is passed over.
///
/// The list of the numbers is made with room for every word of the rest of the response, so
/// it does not grow while it fills: a response of numbers holds its text and four bytes for
/// each of its words, and a word with the blank in front of it is two bytes of the text at
/// the least.
fn search(cursor: &mut Cursor<'_>) -> Vec<u32> {
    let words = cursor
        .text
        .get(cursor.at..)
        .unwrap_or_default()
        .split(|byte| *byte == b' ')
        .filter(|word| !word.is_empty())
        .count();
    let mut found = Vec::new();
    // Without the room, the list grows with the numbers it takes.
    let _ = found.try_reserve_exact(words);
    while let Some(Token::Atom(atom)) = cursor.next(false) {
        match number(atom) {
            Some(value) => found.push(value),
            None => break,
        }
    }
    found
}

/// `FETCH (name value ...)`: the items a node asks for. The value of every other item is
/// passed over. `None` for a response in another form.
fn fetch(cursor: &mut Cursor<'_>, literals: &mut [Vec<u8>]) -> Option<Fetched> {
    if cursor.next(false)? != Token::Open {
        return None;
    }
    let mut fetched = Fetched::default();
    loop {
        let name = match cursor.next(true)? {
            Token::Close => return Some(fetched),
            Token::Atom(name) => name,
            Token::Open | Token::Quoted(_) | Token::Literal(_) => return None,
        };
        let is = |item: &[u8]| name.eq_ignore_ascii_case(item);
        if is(b"UID") {
            let Token::Atom(value) = cursor.next(false)? else {
                return None;
            };
            fetched.uid = Some(number(value)?);
        } else if is(b"RFC822.SIZE") {
            let Token::Atom(value) = cursor.next(false)? else {
                return None;
            };
            fetched.size = Some(wide_number(value)?);
        } else if is(b"BODY[HEADER]") || is(b"RFC822.HEADER") {
            fetched.header = string(cursor.next(false)?, literals)
                .ok()?
                .or(fetched.header);
        } else if is(b"BODY[]") || is(b"RFC822") {
            fetched.body = string(cursor.next(false)?, literals).ok()?.or(fetched.body);
        } else if !cursor.skip() {
            return None;
        }
    }
}

/// An IMAP quoted string of `text` (RFC 3501 section 4.3): the text between two quotes, with
/// a backslash in front of every quote and every backslash. `text` holds no line end.
pub(crate) fn quoted(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len().saturating_add(2));
    quoted.push('"');
    for character in text.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The steps of `input`, fed to a reader in pieces of `piece` bytes, with every declared
    /// literal admitted.
    fn steps(input: &[u8], piece: usize) -> Vec<Step> {
        let mut reader = Reader::default();
        let mut found = Vec::new();
        for chunk in input.chunks(piece) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let (taken, step) = reader.feed(rest);
                rest = &rest[taken..];
                match step {
                    Step::More => assert!(rest.is_empty()),
                    Step::Literal(_) => reader.admit(),
                    step => found.push(step),
                }
            }
        }
        assert!(reader.at_rest(), "{reader:?}");
        found
    }

    fn responses(input: &[u8], piece: usize) -> Vec<Option<Response>> {
        steps(input, piece)
            .into_iter()
            .map(|step| match step {
                Step::Response(raw) => parse(raw),
                other => panic!("{other:?}"),
            })
            .collect()
    }

    fn status_of(condition: Condition, code: Code, behind: &str) -> Status {
        Status {
            condition,
            code,
            behind: behind.as_bytes().to_vec(),
        }
    }

    fn ok(behind: &str, code: Code) -> Status {
        status_of(Condition::Ok, code, behind)
    }

    #[test]
    fn the_responses_of_a_read_are_read_however_their_bytes_arrive() {
        let input: &[u8] = b"* OK [CAPABILITY IMAP4rev1] ready\r\n\
            a1 OK LOGIN completed\r\n\
            * LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
            * LIST () \"/\" {5}\r\nhe)lo\r\n\
            * LIST (\\Noselect) NIL inbox\r\n\
            * LIST (\\HasNoChildren) \"/\" \"a \\\"b\\\\c\"\r\n\
            * 3 EXISTS\r\n\
            * OK [UIDVALIDITY 42] valid\r\n\
            * OK [UIDNEXT 8] next\r\n\
            a2 OK [READ-ONLY] done\r\n\
            * SEARCH 7 9 4294967295\r\n\
            * SEARCH\r\n\
            * SEARCH 2 5 (MODSEQ 917162500)\r\n\
            * 2 FETCH (FLAGS (\\Seen (nested \"a)b\")) UID 99)\r\n\
            * 1 FETCH (UID 7 RFC822.SIZE 12 BODY[HEADER] {9}\r\n{99999}\r\n INTERNALDATE NIL BODY[] \"q\\\"\")\r\n\
            * 4 FETCH (BODY[HEADER.FIELDS (DATE FROM)] {4}\r\nD: 1 uid 3 rfc822.size 5000000000 body[] {0}\r\n)\r\n\
            + send it\r\n\
            a3 NO [AUTHENTICATIONFAILED] Invalid {3}\r\n\
            * BYE gone\r\n";
        let expected = vec![
            Some(Response::Untagged(ok(
                "[CAPABILITY IMAP4rev1] ready",
                Code::Other,
            ))),
            Some(Response::Tagged(
                b"a1".to_vec(),
                ok("LOGIN completed", Code::Other),
            )),
            Some(Response::List("INBOX".to_string())),
            Some(Response::List("he)lo".to_string())),
            Some(Response::List("INBOX".to_string())),
            Some(Response::List("a \"b\\c".to_string())),
            Some(Response::Other),
            Some(Response::Untagged(ok(
                "[UIDVALIDITY 42] valid",
                Code::UidValidity(42),
            ))),
            Some(Response::Untagged(ok("[UIDNEXT 8] next", Code::UidNext(8)))),
            Some(Response::Tagged(
                b"a2".to_vec(),
                ok("[READ-ONLY] done", Code::Other),
            )),
            Some(Response::Search(vec![7, 9, u32::MAX])),
            Some(Response::Search(Vec::new())),
            Some(Response::Search(vec![2, 5])),
            Some(Response::Fetch(Fetched {
                uid: Some(99),
                ..Fetched::default()
            })),
            Some(Response::Fetch(Fetched {
                uid: Some(7),
                size: Some(12),
                header: Some(b"{99999}\r\n".to_vec()),
                body: Some(b"q\"".to_vec()),
            })),
            Some(Response::Fetch(Fetched {
                uid: Some(3),
                size: Some(5_000_000_000),
                header: None,
                body: Some(Vec::new()),
            })),
            Some(Response::Continue),
            Some(Response::Tagged(
                b"a3".to_vec(),
                status_of(
                    Condition::No,
                    Code::Other,
                    "[AUTHENTICATIONFAILED] Invalid {3}",
                ),
            )),
            Some(Response::Untagged(status_of(
                Condition::Bye,
                Code::Other,
                "gone",
            ))),
        ];
        for piece in [1, 2, 3, 7, 64, input.len()] {
            assert_eq!(responses(input, piece), expected, "pieces of {piece}");
        }
    }

    /// Three responses a server can send that end the parser of the crate imap-proto 0.17.0
    /// with a panic: a character outside ASCII directly behind the response code of a tagged
    /// and of an untagged status response (a slice of a text at a place that is no character
    /// boundary), and `INTERNALDATE NIL` (an `unwrap`). Each is read here as what it says.
    #[test]
    fn a_character_outside_ascii_behind_a_response_code_and_a_nil_date_are_read() {
        let found = responses(
            "a1 OK [READ-WRITE]é done\r\n\
             * OK [ALERT]한 x\r\n\
             * 1 FETCH (INTERNALDATE NIL UID 5)\r\n"
                .as_bytes(),
            1,
        );
        assert_eq!(
            found,
            [
                Some(Response::Tagged(
                    b"a1".to_vec(),
                    ok("[READ-WRITE]é done", Code::Other)
                )),
                Some(Response::Untagged(ok("[ALERT]한 x", Code::Other))),
                Some(Response::Fetch(Fetched {
                    uid: Some(5),
                    ..Fetched::default()
                })),
            ]
        );
    }

    /// The lines imap.naver.com sent on 2026-11-23 around a refused login. The name of the
    /// login stands in the text of its refusal.
    #[test]
    fn the_lines_of_the_naver_server_are_read() {
        let found = responses(
            b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR ID CHILDREN UIDPLUS LIST-EXTENDED \
              SPECIAL-USE UNSELECT QUOTA MOVE AUTH=PLAIN APPENDLIMIT=41943040] Naver Imap \
              Server ready.\r\n\
              * CAPABILITY IMAP4rev1 LITERAL+ SASL-IR ID CHILDREN UIDPLUS LIST-EXTENDED \
              SPECIAL-USE UNSELECT QUOTA MOVE AUTH=PLAIN APPENDLIMIT=41943040\r\n\
              p1 OK Capability completed.\r\n\
              p2 NO [AUTH] \"name{12}\": Authentication failed. (Please check your username, \
              password)\r\n\
              p3 BAD Error in IMAP command EXAMINE: bad syntax\r\n\
              * BYE Logging out\r\n\
              p4 OK Logout completed.\r\n\
              * OK [UIDVALIDITY 0] UIDs valid\r\n",
            11,
        );
        assert_eq!(found.len(), 8);
        assert!(matches!(
            &found[0],
            Some(Response::Untagged(status)) if status.condition == Condition::Ok
        ));
        assert_eq!(found[1], Some(Response::Other));
        let Some(Response::Tagged(tag, refusal)) = &found[3] else {
            panic!("{:?}", found[3]);
        };
        assert_eq!(
            (tag.as_slice(), refusal.condition),
            (&b"p2"[..], Condition::No)
        );
        assert!(refusal.mentions(b"authentication failed"));
        assert!(!refusal.mentions(b"authenticationfailed"));
        assert!(!refusal.mentions(b""));
        assert!(matches!(
            &found[4],
            Some(Response::Tagged(_, status)) if status.condition == Condition::Bad
        ));
        assert!(matches!(
            &found[5],
            Some(Response::Untagged(status)) if status.condition == Condition::Bye
        ));
        // imap.naver.com answers `EXAMINE "INBOX"` with the generation 0.
        assert!(matches!(
            &found[7],
            Some(Response::Untagged(status)) if status.code == Code::UidValidity(0)
        ));
    }

    #[test]
    fn a_status_response_is_one_line_whatever_stands_at_its_end() {
        // The text of a status response reaches to the end of its line: `{30}` declares
        // nothing there, and the line that follows is a response of its own.
        let input = b"* OK {30}\r\n* 1 FETCH (BODY[] {4}\r\nbody)\r\na1 BAD {7}\r\n+ {2}\r\n\
            * NO [TRYCREATE] Mailbox doesn't exist: x{100000}\r\n* bye {5}\r\n";
        let found = responses(input, 5);
        assert_eq!(found.len(), 6);
        assert_eq!(found[0], Some(Response::Untagged(ok("{30}", Code::Other))));
        assert_eq!(
            found[1],
            Some(Response::Fetch(Fetched {
                body: Some(b"body".to_vec()),
                ..Fetched::default()
            }))
        );
        assert!(matches!(found[2], Some(Response::Tagged(_, _))));
        assert_eq!(found[3], Some(Response::Continue));
        assert!(matches!(
            &found[4],
            Some(Response::Untagged(status)) if status.condition == Condition::No
        ));
        assert!(matches!(
            &found[5],
            Some(Response::Untagged(status)) if status.condition == Condition::Bye
        ));
    }

    #[test]
    fn a_declaration_is_reported_before_a_byte_behind_it_is_taken() {
        let mut reader = Reader::default();
        let input = b"* 1 FETCH (BODY[] {40}\r\nxxxx";
        let (taken, step) = reader.feed(input);
        assert_eq!((taken, step), (24, Step::Literal(40)));
        // Until the literal is admitted the reader takes nothing.
        assert_eq!(reader.feed(&input[taken..]), (0, Step::Literal(40)));
        reader.admit();
        assert_eq!(reader.feed(&input[taken..]), (4, Step::More));
        assert!(!reader.at_rest());

        // A declaration of more digits than a number of 64 bits has, and one above it. The
        // reader is at rest again behind it.
        for digits in ["184467440737095516150", "18446744073709551616"] {
            let mut reader = Reader::default();
            let line = format!("* 1 FETCH (BODY[] {{{digits}}}\r\n");
            assert_eq!(reader.feed(line.as_bytes()).1, Step::Malformed);
            assert!(reader.at_rest());
        }
        // Braces that hold no number declare nothing.
        assert_eq!(
            responses(b"* LIST () \"/\" a{}\r\n* LIST () \"/\" b{x}\r\n", 64).len(),
            2
        );
        // A line feed without a carriage return in front of it ends a line as well.
        assert_eq!(
            responses(b"* SEARCH 1\n* SEARCH 2\r\n", 3),
            [
                Some(Response::Search(vec![1])),
                Some(Response::Search(vec![2]))
            ]
        );
    }

    #[test]
    fn bytes_that_are_no_response_are_refused_and_end_nothing() {
        for input in [
            &b" \r\n"[..],
            b"a1\r\n",
            b"a1 MAYBE\r\n",
            b"* LIST\r\n",
            b"* LIST (\r\n",
            b"* LIST () \"/\r\n",
            b"* LIST () (a) b\r\n",
            b"* LIST () \"/\"\r\n",
            b"* 1 FETCH\r\n",
            b"* 1 FETCH (UID\r\n",
            b"* 1 FETCH (UID x)\r\n",
            b"* 1 FETCH (UID 99999999999)\r\n",
            b"* 1 FETCH (RFC822.SIZE 99999999999999999999999)\r\n",
            b"* 1 FETCH (BODY[] (a))\r\n",
            b"* 1 FETCH (FLAGS (a (b (c)\r\n",
            b"* 1 FETCH (\"UID\" 1)\r\n",
            b"* 1 FETCH (BODY[] \"a{2}\r\nxy\")\r\n",
        ] {
            assert_eq!(
                responses(input, 64),
                [None],
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
        // What a node does not read is passed over.
        for input in [
            &b"\r\n"[..],
            b"* CAPABILITY IMAP4rev1 LITERAL+\r\n",
            b"* FLAGS (\\Seen)\r\n",
            b"* 5 RECENT\r\n",
            b"* 5\r\n",
            b"* \r\n",
            b"* STATUS \"a\" (MESSAGES 1)\r\n",
            b"* ID (\"name\" {3}\r\nabc)\r\n",
            // A folder whose name a node cannot put into a command.
            b"* LIST () \"/\" \"\"\r\n",
            b"* LIST () \"/\" \"a\x01b\"\r\n",
            b"* LIST () \"/\" \"\xff\xfe\"\r\n",
        ] {
            assert_eq!(
                responses(input, 64),
                [Some(Response::Other)],
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
        // The name of a folder is a string or an atom: the atom `NIL` is the name `NIL` there.
        assert_eq!(
            responses(b"* LIST () \"/\" NIL\r\n* LIST () \"/\" a[b]c\r\n", 64),
            [
                Some(Response::List("NIL".to_string())),
                Some(Response::List("a[b]c".to_string()))
            ]
        );
        // A folder name of the longest length is handed on, and one byte more is not.
        let longest = format!("* LIST () \"/\" {}\r\n", "n".repeat(FOLDER_NAME_BYTES));
        assert!(matches!(
            responses(longest.as_bytes(), 4096).as_slice(),
            [Some(Response::List(_))]
        ));
        let longer = format!("* LIST () \"/\" {}\r\n", "n".repeat(FOLDER_NAME_BYTES + 1));
        assert_eq!(responses(longer.as_bytes(), 4096), [Some(Response::Other)]);
        // A list ten thousand lists deep is passed over.
        let deep = format!(
            "* 1 FETCH (X {}{} UID 5)\r\n",
            "(".repeat(10_000),
            ")".repeat(10_000)
        );
        assert_eq!(
            responses(deep.as_bytes(), 4096),
            [Some(Response::Fetch(Fetched {
                uid: Some(5),
                ..Fetched::default()
            }))]
        );
    }

    /// A generator of numbers that gives the same numbers on every run.
    struct Numbers(u64);

    impl Numbers {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound.max(1) as u64) as usize
        }
    }

    /// Feeds `input` in pieces of lengths drawn from `numbers` and reads every response,
    /// with every declared literal up to `bound` octets admitted, as the connection of a mail
    /// call does. Returns the responses that were read. What it shows is that it returns.
    fn read_all(input: &[u8], numbers: &mut Numbers, bound: u64) -> Vec<Option<Response>> {
        let mut reader = Reader::default();
        let mut found = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let piece = (1 + numbers.below(40)).min(rest.len());
            let mut chunk = &rest[..piece];
            rest = &rest[piece..];
            loop {
                let (taken, step) = reader.feed(chunk);
                assert!(taken <= chunk.len());
                chunk = &chunk[taken..];
                match step {
                    Step::More => {
                        assert!(chunk.is_empty());
                        break;
                    }
                    Step::Literal(octets) if octets <= bound => reader.admit(),
                    Step::Literal(_) | Step::Malformed => return found,
                    Step::Response(raw) => {
                        let held =
                            raw.text.len() + raw.literals.iter().map(Vec::len).sum::<usize>();
                        assert!(held <= input.len());
                        found.push(parse(raw));
                    }
                }
            }
        }
        found
    }

    /// No bytes end the reader: responses of every kind a node reads, with bytes changed,
    /// removed, repeated and cut, and bytes drawn at random, are read to their end.
    #[test]
    fn no_bytes_end_the_reader() {
        let seeds: [&[u8]; 9] = [
            b"* OK [CAPABILITY IMAP4rev1 LITERAL+] ready\r\na1 OK done\r\n",
            b"* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent Messages\"\r\n* LIST () NIL {3}\r\nabc\r\n",
            b"* 2 EXISTS\r\n* OK [UIDVALIDITY 0] valid\r\n* OK [UIDNEXT 8] next\r\na2 OK [READ-ONLY] done\r\n",
            b"* SEARCH 1 2 3 4294967295 (MODSEQ 5)\r\na3 OK done\r\n",
            b"* 1 FETCH (UID 7 RFC822.SIZE 44 BODY[HEADER] {12}\r\nSubject: a\r\n FLAGS (\\Seen))\r\n",
            b"* 1 FETCH (FLAGS (\\Seen) INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" BODY[] {5}\r\nhello UID 9)\r\n",
            "a1 OK [READ-WRITE]é done\r\n* OK [ALERT]한 x\r\n* 1 FETCH (INTERNALDATE NIL UID 5)\r\n"
                .as_bytes(),
            b"+ go ahead\r\n* BYE [ALERT] closing {9}\r\na4 NO [AUTH] \"n\": Authentication failed.\r\n",
            b"* 3 FETCH (ENVELOPE (NIL \"s\" ((NIL NIL \"a\" \"b\")) NIL) BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 2 1)) BODY[HEADER.FIELDS (X)] {2}\r\nX: UID 3)\r\n",
        ];
        let mut numbers = Numbers(0x9e37_79b9_7f4a_7c15);
        let pieces: &[&[u8]] = &[
            b"{",
            b"}",
            b"{0}",
            b"{3}",
            b"{18446744073709551615}",
            b"\r\n",
            b"\n",
            b"\r",
            b"\"",
            b"\\",
            b"(",
            b")",
            b"[",
            b"]",
            b" ",
            b"*",
            b"+",
            b"NIL",
            b"FETCH",
            b"LIST",
            b"SEARCH",
            b"UID",
            b"BODY[]",
            b"BODY[HEADER]",
            b"RFC822.SIZE",
            b"OK",
            b"NO",
            b"BYE",
            b"\x00",
            b"\xff",
            b"\xed\x95\x9c",
            b"4294967296",
            b"99999999999999999999",
        ];
        for round in 0..60_000 {
            let mut input = seeds[numbers.below(seeds.len())].to_vec();
            for _ in 0..numbers.below(6) {
                let at = numbers.below(input.len() + 1);
                match numbers.below(6) {
                    0 if at < input.len() => input[at] = numbers.next() as u8,
                    1 if at < input.len() => {
                        input.remove(at);
                    }
                    2 => {
                        let piece = pieces[numbers.below(pieces.len())];
                        input.splice(at..at, piece.iter().copied());
                    }
                    3 => {
                        let other = seeds[numbers.below(seeds.len())];
                        let from = numbers.below(other.len());
                        let to = from + numbers.below(other.len() - from + 1);
                        input.splice(at..at, other[from..to].iter().copied());
                    }
                    4 => input.truncate(at),
                    _ => {
                        let count = numbers.below(24);
                        let random: Vec<u8> = (0..count).map(|_| numbers.next() as u8).collect();
                        input.splice(at..at, random);
                    }
                }
            }
            let bound = match round % 3 {
                0 => 0,
                1 => 64,
                _ => 1024 * 1024,
            };
            read_all(&input, &mut numbers, bound);
        }
    }

    /// A response that is whole is read to the same value in whatever pieces its bytes
    /// arrive: the reader keeps no place that depends on where a piece ends.
    #[test]
    fn the_reading_of_a_response_does_not_depend_on_its_pieces() {
        let mut numbers = Numbers(0x2545_f491_4f6c_dd1d);
        let alphabet: &[&[u8]] = &[
            b"* ",
            b"a1 ",
            b"OK ",
            b"NO ",
            b"LIST ",
            b"SEARCH ",
            b"1 FETCH ",
            b"(",
            b")",
            b" ",
            b"\"q\" ",
            b"NIL ",
            b"UID 4 ",
            b"BODY[] ",
            b"BODY[HEADER] ",
            b"RFC822.SIZE 9 ",
            b"{2}\r\nab",
            b"{0}\r\n",
            b"\\Seen ",
            b"x",
            b"7 ",
            b"[UIDNEXT 3] ",
            b"\r\n",
        ];
        for _ in 0..4_000 {
            let mut input = Vec::new();
            for _ in 0..1 + numbers.below(30) {
                input.extend_from_slice(alphabet[numbers.below(alphabet.len())]);
            }
            input.extend_from_slice(b"\r\n");
            let whole = read_all(&input, &mut Numbers(1), u64::MAX);
            for _ in 0..4 {
                assert_eq!(
                    read_all(&input, &mut numbers, u64::MAX),
                    whole,
                    "{:?}",
                    String::from_utf8_lossy(&input)
                );
            }
        }
    }

    #[test]
    fn a_quoted_string_escapes_its_quotes_and_backslashes() {
        assert_eq!(quoted("INBOX"), "\"INBOX\"");
        assert_eq!(quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quoted(""), "\"\"");
        assert_eq!(quoted("받은 편지"), "\"받은 편지\"");
    }
}
