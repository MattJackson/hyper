//! Blocks holding a peer's bytes are wiped before they go back to the allocator.
//!
//! A request head carries credentials (an `Authorization` value, a cookie, a token in the path).
//! The read buffer the head is parsed from, the slices a parsed head hands out (header values,
//! the URI) and the body chunks read from it all live in blocks of memory that are freed when
//! the last of them is dropped. Freed as they are, the credential stays readable in freed
//! memory for as long as the allocator leaves it there.
//!
//! So every byte read from the peer is wiped before its block is released:
//!
//! - the read buffer is a [`WipingBuf`]: its filled bytes are wiped when it is dropped, and when
//!   it grows into a new block the old block is wiped before it is freed;
//! - what is taken out of it ([`split_to`], [`hold`]) is copied once into a block that wipes
//!   itself when the last `Bytes` sharing it is dropped, and the bytes left behind in the read
//!   buffer's block are wiped at once.
//!
//! The same bytes are read and parsed in the same order; only the release changes.

use std::fmt;
use std::ops::{Deref, DerefMut};

use bytes::{Bytes, BytesMut};
use zeroize::Zeroize;

/// A block holding a copy of a peer's bytes; wiped before it is freed.
struct Wiped(Box<[u8]>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0[..].zeroize();
    }
}

/// Moves the bytes of `taken` into a block that wipes itself when the last `Bytes` sharing it
/// is dropped, and wipes `taken` where it stands.
pub(crate) fn hold(taken: &mut BytesMut) -> Bytes {
    if taken.is_empty() {
        return Bytes::new();
    }
    let held = Bytes::from_owner(Wiped(Box::from(&taken[..])));
    taken[..].zeroize();
    held
}

/// Splits the first `at` bytes off `buf` into a wiping block (see [`hold`]); the bytes left
/// behind in `buf`'s block are wiped.
pub(crate) fn split_to(buf: &mut BytesMut, at: usize) -> Bytes {
    let mut taken = buf.split_to(at);
    hold(&mut taken)
}

/// The read buffer: a `BytesMut` whose filled bytes are wiped before its block is released.
pub(crate) struct WipingBuf(BytesMut);

impl WipingBuf {
    pub(crate) fn with_capacity(capacity: usize) -> WipingBuf {
        WipingBuf(BytesMut::with_capacity(capacity))
    }

    /// Makes room for at least `additional` more bytes. When that takes a new block, the filled
    /// bytes are copied into it and the old block is wiped before it is freed (`BytesMut::reserve`
    /// would free or reuse it with the bytes still in it).
    pub(crate) fn reserve(&mut self, additional: usize) {
        if self.0.capacity() - self.0.len() >= additional {
            return;
        }
        let mut grown = BytesMut::with_capacity(self.0.len() + additional);
        grown.extend_from_slice(&self.0);
        self.0[..].zeroize();
        self.0 = grown;
    }

    /// Hands the filled bytes over in a wiping block (see [`hold`]).
    pub(crate) fn into_bytes(mut self) -> Bytes {
        hold(&mut self.0)
    }
}

impl Deref for WipingBuf {
    type Target = BytesMut;

    fn deref(&self) -> &BytesMut {
        &self.0
    }
}

impl DerefMut for WipingBuf {
    fn deref_mut(&mut self) -> &mut BytesMut {
        &mut self.0
    }
}

impl fmt::Debug for WipingBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Drop for WipingBuf {
    fn drop(&mut self) {
        self.0[..].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"authorization: Bearer sk-wipe-test-0123456789";

    #[test]
    fn hold_keeps_the_bytes_and_wipes_where_they_stood() {
        let mut taken = BytesMut::from(SECRET);
        let held = hold(&mut taken);
        assert_eq!(&held[..], SECRET);
        assert_eq!(taken.len(), SECRET.len());
        assert!(taken.iter().all(|b| *b == 0));
    }

    #[test]
    fn split_to_takes_the_front_and_wipes_it_in_the_buffer() {
        let mut buf = BytesMut::from(SECRET);
        buf.extend_from_slice(b"\r\n\r\nbody");
        let head = split_to(&mut buf, SECRET.len());
        assert_eq!(&head[..], SECRET);
        assert_eq!(&buf[..], b"\r\n\r\nbody");
        // The wiping block's slices share it and read the same bytes.
        assert_eq!(&head.slice(15..21)[..], b"Bearer");
    }

    #[test]
    fn hold_of_nothing_is_empty() {
        let mut taken = BytesMut::new();
        assert!(hold(&mut taken).is_empty());
    }

    #[test]
    fn reserve_keeps_the_filled_bytes_when_it_moves_them() {
        let mut buf = WipingBuf::with_capacity(8);
        buf.extend_from_slice(&SECRET[..8]);
        buf.reserve(4096);
        assert!(buf.capacity() - buf.len() >= 4096);
        buf.extend_from_slice(&SECRET[8..]);
        assert_eq!(&buf[..], SECRET);
        // Room already there: nothing moves.
        let before = buf.as_ptr();
        buf.reserve(1);
        assert_eq!(buf.as_ptr(), before);
    }

    #[test]
    fn into_bytes_hands_over_the_filled_bytes() {
        let mut buf = WipingBuf::with_capacity(0);
        buf.reserve(SECRET.len());
        buf.extend_from_slice(SECRET);
        assert_eq!(&buf.into_bytes()[..], SECRET);
    }
}
