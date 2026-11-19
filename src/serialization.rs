//! Optional labels for outgoing bytes.
//!
//! A connection built with a [`Labels`] sink reports, in the order it encodes, which message each run of
//! encoded bytes belongs to, whether the run is body or control, where a sealed value goes, and when a
//! message's last unit is encoded. The labels describe encoded bytes, never socket progress. Every call is
//! infallible and synchronous; nothing is batched, held or counted on the sink's behalf.
//!
//! Both roles label: a server its responses, a client its requests.

use std::fmt;

/// How the encoder finished a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The last unit is encoded: the message is complete once flushed.
    Flush,
    /// The message is complete only when the connection is shut down (a close-delimited HTTP/1 body).
    Shutdown,
    /// The message was given up; the code is the protocol's (an HTTP/2 reason), 0 when there is none.
    Failed(u32),
}

/// A connection's label sink.
///
/// `stream` names the message. On HTTP/1 it is what [`Labels::message`] returned for the message being
/// encoded. On HTTP/2 it is the wire stream identifier. 0 is the connection itself.
pub trait Labels: Send + Sync + fmt::Debug {
    /// HTTP/1 only. The name of the message whose head is about to be encoded: a response on a server, a
    /// request on a client. Called once per message, in wire order. 0: the message is the connection's own
    /// (never happens for a message the application supplied).
    fn message(&self) -> u64;
    /// HTTP/2 client only. The request submitted next, in the order requests were handed to the
    /// connection, was given wire stream `wire`; or (`None`) was dropped before a stream was opened for
    /// it. Exactly one call per submitted request.
    fn request(&self, wire: Option<u32>) {
        let _ = wire;
    }
    /// `len` bytes (never 0) were encoded for `stream`. `payload`: they are bytes of the message body, one
    /// for one; else head, trailers, framing or connection control.
    fn span(&self, stream: u64, payload: bool, len: usize);
    /// The bytes `offset..offset + len` of sealed value `slot` of `stream` belong here. The encoder wrote
    /// nothing for them: whoever owns the connection supplies them.
    fn sealed(&self, stream: u64, slot: u32, offset: u32, len: u32);
    /// Nothing more will be encoded for `stream`.
    fn end(&self, stream: u64, how: End);
}

/// Request extension (client): the places in the request target where a sealed value goes.
///
/// The target the application supplies holds a filler of `len` bytes at each `offset` (offsets into the
/// path-and-query as supplied, ascending, not overlapping). The encoder writes no byte of a filler and
/// states [`Labels::sealed`] in its place. The spans are slots 0, 1, 2, ... in order.
///
/// A request header value marked sensitive (`HeaderValue::set_sensitive`) on a connection with a label
/// sink is a sealed value too: its bytes are a filler of the value's length, never written. Header slots
/// are numbered in encoding order, continuing after the target's.
#[derive(Clone, Debug, Default)]
pub struct SealedTarget(pub Vec<SealedSpan>);

/// One sealed place in a request target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedSpan {
    /// Offset of the filler in the supplied path-and-query.
    pub offset: u32,
    /// Length of the filler: the length of the sealed value.
    pub len: u32,
}

/// One sealed place in an encoded HTTP/1 head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    /// Index in the head buffer (after earlier fillers were left out) where the value belongs.
    pub(crate) at: usize,
    pub(crate) slot: u32,
    pub(crate) len: u32,
}

/// The sealed places of the head being encoded. Empty, and without memory, unless the head has one.
#[derive(Debug, Default)]
pub(crate) struct Marks {
    pub(crate) on: bool,
    pub(crate) list: Vec<Mark>,
    next_slot: u32,
}

impl Marks {
    /// For a connection with a sink: sensitive values are sealed.
    pub(crate) fn on() -> Self {
        Marks {
            on: true,
            list: Vec::new(),
            next_slot: 0,
        }
    }
    /// A sealed value of `len` bytes belongs at `at`.
    pub(crate) fn push(&mut self, at: usize, len: usize) {
        if len == 0 {
            return;
        }
        self.list.push(Mark {
            at,
            slot: self.next_slot,
            len: len as u32,
        });
        self.next_slot += 1;
    }
}

/// States the labels of one encoded head: the bytes `start..head_len` of the head buffer, with `marks`
/// (indexes into that buffer).
pub(crate) fn state_head(
    labels: &dyn Labels,
    stream: u64,
    start: usize,
    head_len: usize,
    marks: &Marks,
) {
    let mut at = start;
    for mark in &marks.list {
        if mark.at > at {
            labels.span(stream, false, mark.at - at);
        }
        labels.sealed(stream, mark.slot, 0, mark.len);
        at = mark.at;
    }
    if head_len > at {
        labels.span(stream, false, head_len - at);
    }
}

/// A run of encoded bytes of one class, as the HTTP/1 body encoder reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    pub(crate) payload: bool,
    pub(crate) len: usize,
}

/// The runs of one encoded body unit (a chunk is size line, data, line end; the last chunk adds the end
/// marker) and whether the unit ends the message. At most five runs.
#[derive(Debug)]
pub(crate) struct Plan {
    runs: [Run; 5],
    len: usize,
    pub(crate) end: Option<End>,
}

impl Plan {
    pub(crate) fn new() -> Self {
        Self {
            runs: [Run {
                payload: false,
                len: 0,
            }; 5],
            len: 0,
            end: None,
        }
    }
    pub(crate) fn control(&mut self, len: usize) {
        self.push(false, len);
    }
    pub(crate) fn payload(&mut self, len: usize) {
        self.push(true, len);
    }
    fn push(&mut self, payload: bool, len: usize) {
        if len == 0 {
            return;
        }
        if self.len > 0 && self.runs[self.len - 1].payload == payload {
            self.runs[self.len - 1].len += len;
            return;
        }
        self.runs[self.len] = Run { payload, len };
        self.len += 1;
    }
    /// The runs of `other` after this plan's.
    pub(crate) fn append(&mut self, other: &Plan) {
        for run in other.as_slice() {
            self.push(run.payload, run.len);
        }
        if other.end.is_some() {
            self.end = other.end;
        }
    }
    pub(crate) fn as_slice(&self) -> &[Run] {
        &self.runs[..self.len]
    }
    /// States the plan for `stream`.
    pub(crate) fn state(&self, labels: &dyn Labels, stream: u64) {
        for run in self.as_slice() {
            labels.span(stream, run.payload, run.len);
        }
        if let Some(how) = self.end {
            labels.end(stream, how);
        }
    }
}

/// The HTTP/2 side: h2 labels each frame with its wire stream; this passes them on.
#[cfg(feature = "http2")]
#[derive(Debug)]
pub(crate) struct H2Labels(pub(crate) std::sync::Arc<dyn Labels>);

#[cfg(feature = "http2")]
impl h2::serialization::Labels for H2Labels {
    fn span(&self, wire: u32, payload: bool, len: usize) {
        self.0.span(u64::from(wire), payload, len);
    }
    fn sealed(&self, wire: u32, slot: u32, offset: u32, len: u32) {
        self.0.sealed(u64::from(wire), slot, offset, len);
    }
    fn end(&self, wire: u32, failed: Option<u32>) {
        let how = match failed {
            None => End::Flush,
            Some(code) => End::Failed(code),
        };
        self.0.end(u64::from(wire), how);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Seen(Mutex<Vec<String>>);
    impl Labels for Seen {
        fn message(&self) -> u64 {
            7
        }
        fn span(&self, stream: u64, payload: bool, len: usize) {
            self.0
                .lock()
                .unwrap()
                .push(format!("span {stream} {payload} {len}"));
        }
        fn sealed(&self, stream: u64, slot: u32, offset: u32, len: u32) {
            self.0
                .lock()
                .unwrap()
                .push(format!("sealed {stream} {slot} {offset} {len}"));
        }
        fn end(&self, stream: u64, how: End) {
            self.0.lock().unwrap().push(format!("end {stream} {how:?}"));
        }
    }

    #[test]
    fn a_head_with_two_sealed_values_is_control_runs_around_the_marks() {
        let seen = Seen::default();
        let mut marks = Marks::on();
        marks.push(10, 4);
        marks.push(30, 9);
        state_head(&seen, 7, 0, 34, &marks);
        assert_eq!(
            *seen.0.lock().unwrap(),
            [
                "span 7 false 10",
                "sealed 7 0 0 4",
                "span 7 false 20",
                "sealed 7 1 0 9",
                "span 7 false 4"
            ]
        );
    }

    #[test]
    fn a_plan_joins_runs_of_one_class_and_states_its_end_last() {
        let seen = Seen::default();
        let mut plan = Plan::new();
        plan.control(3);
        plan.payload(5);
        plan.control(2);
        plan.control(5);
        plan.end = Some(End::Flush);
        plan.state(&seen, 7);
        assert_eq!(
            *seen.0.lock().unwrap(),
            [
                "span 7 false 3",
                "span 7 true 5",
                "span 7 false 7",
                "end 7 Flush"
            ]
        );
    }
}
