//! Optional exact outgoing serialization observations.
//!
//! These facts describe encoded bytes, never socket progress. An observer must
//! accept a whole batch atomically or return an error. A consumer implementing
//! release barriers must retain the ordered terminal suffix until authorization.

use std::{fmt, io, num::NonZeroU64};

/// Application identity carried on a response, independent of HTTP/2 wire IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseIdentity(pub NonZeroU64);

/// Classification of actual encoded bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializedClass {
    /// Protocol head, framing or connection control.
    Control,
    /// Actual response body bytes, excluding protocol framing.
    Payload,
}

/// Carrier operation required after the attributed byte prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionRequirement {
    /// Flush the attributed prefix.
    Flush,
    /// Flush and shut down the real carrier (close-delimited HTTP/1).
    Shutdown,
}

/// An ordered serializer fact; lifecycle facts consume no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializedEvent {
    /// A nonempty encoded byte interval. Zero identity means connection control.
    Span {
        /// Application response identity.
        stream: u64,
        /// Actual byte class.
        class: SerializedClass,
        /// Number of encoded bytes.
        len: u64,
    },
    /// Authorization must precede emission of the following terminal unit.
    ReleaseBarrier {
        /// Application response identity.
        stream: u64,
    },
    /// Successful serialization ended, independently of delivery and input EOF.
    End {
        /// Application response identity.
        stream: u64,
        /// Required real carrier completion operation.
        requirement: CompletionRequirement,
    },
    /// The protocol failed this response; never a successful end.
    Abort {
        /// Application response identity.
        stream: u64,
    },
    /// No serializer producer can create more bytes for this response.
    Quiescent {
        /// Application response identity.
        stream: u64,
    },
}

/// Connection-scoped, bounded sink for exact serialization facts.
pub trait SerializationObserver: Send + Sync + fmt::Debug {
    /// Atomically reserve and append all facts, or fail without accepting any.
    /// Errors poison serialization before the failed batch reaches IO.
    fn record(&self, events: &[SerializedEvent]) -> io::Result<()>;
    /// Maximum number of admitted live responses, including unsettled endings.
    fn response_capacity(&self) -> usize;
    /// Whether the admitted response still owns its lifecycle slot.
    fn is_live(&self, stream: u64) -> bool;
    /// Poll audited terminal authorization, retaining at most one waker.
    fn poll_release(
        &self,
        stream: u64,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>>;
}

#[derive(Debug)]
pub(crate) struct Plan {
    events: [SerializedEvent; 8],
    len: usize,
}

impl Plan {
    pub(crate) fn new() -> Self {
        Self {
            events: [SerializedEvent::Quiescent { stream: 0 }; 8],
            len: 0,
        }
    }
    pub(crate) fn push(&mut self, event: SerializedEvent) {
        self.events[self.len] = event;
        self.len += 1;
    }
    pub(crate) fn span(&mut self, stream: u64, class: SerializedClass, len: usize) {
        if len != 0 {
            self.push(SerializedEvent::Span {
                stream,
                class,
                len: len as u64,
            });
        }
    }
    pub(crate) fn barrier(&mut self, stream: u64) {
        if stream != 0 {
            self.push(SerializedEvent::ReleaseBarrier { stream });
        }
    }
    pub(crate) fn end(&mut self, stream: u64, requirement: CompletionRequirement) {
        if stream != 0 {
            self.push(SerializedEvent::End {
                stream,
                requirement,
            });
            self.push(SerializedEvent::Quiescent { stream });
        }
    }
    pub(crate) fn as_slice(&self) -> &[SerializedEvent] {
        &self.events[..self.len]
    }
}

#[cfg(feature = "http2")]
#[derive(Debug)]
pub(crate) struct H2Observer {
    observer: std::sync::Arc<dyn SerializationObserver>,
    bindings: std::sync::Mutex<Vec<(u32, std::sync::Arc<h2::serialization::ResponseState>)>>,
    limit: usize,
}
#[cfg(feature = "http2")]
impl H2Observer {
    pub(crate) fn new(observer: std::sync::Arc<dyn SerializationObserver>) -> Self {
        let limit = observer.response_capacity();
        Self {
            observer,
            bindings: std::sync::Mutex::new(Vec::with_capacity(limit)),
            limit,
        }
    }
}
#[cfg(feature = "http2")]
impl h2::serialization::Observer for H2Observer {
    fn record(&self, events: &[h2::serialization::Event]) -> io::Result<()> {
        use h2::serialization::Event;
        let mut plan = Plan::new();
        if events.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialization batch too large",
            ));
        }
        for event in events {
            plan.push(match *event {
                Event::Span {
                    stream,
                    payload,
                    len,
                } => SerializedEvent::Span {
                    stream,
                    class: if payload {
                        SerializedClass::Payload
                    } else {
                        SerializedClass::Control
                    },
                    len,
                },
                Event::ReleaseBarrier { stream } => SerializedEvent::ReleaseBarrier { stream },
                Event::End { stream } => SerializedEvent::End {
                    stream,
                    requirement: CompletionRequirement::Flush,
                },
                Event::Abort { stream } => SerializedEvent::Abort { stream },
                Event::Quiescent { stream } => SerializedEvent::Quiescent { stream },
            });
        }
        self.observer.record(plan.as_slice())
    }
    fn bind(
        &self,
        wire: u32,
        host: u64,
    ) -> io::Result<std::sync::Arc<h2::serialization::ResponseState>> {
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "binding lock poisoned"))?;
        bindings.retain(|(_, state)| self.observer.is_live(state.identity()));
        if !self.observer.is_live(host)
            || bindings.len() >= self.limit
            || bindings
                .iter()
                .any(|(id, state)| *id == wire || state.identity() == host)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response binding",
            ));
        }
        let state = std::sync::Arc::new(h2::serialization::ResponseState::new(host));
        bindings.push((wire, state.clone()));
        Ok(state)
    }
    fn reset(&self, wire: u32) -> io::Result<()> {
        let state = {
            let bindings = self
                .bindings
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "binding lock poisoned"))?;
            bindings
                .iter()
                .find(|(id, state)| *id == wire && self.observer.is_live(state.identity()))
                .map(|(_, state)| state.clone())
        };
        if let Some(state) = state {
            state.abort(self)?;
        }
        Ok(())
    }
    fn connection_error(&self) -> io::Result<()> {
        let bindings = self
            .bindings
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "binding lock poisoned"))?;
        for (_, state) in bindings
            .iter()
            .filter(|(_, state)| self.observer.is_live(state.identity()))
        {
            state.abort(self)?;
        }
        Ok(())
    }
    fn poll_release(
        &self,
        host: u64,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.observer.poll_release(host, cx)
    }
}

/// Admission-time binder to an actual HTTP/2 responder; request extension.
#[cfg(feature = "http2")]
#[derive(Clone, Debug)]
pub struct ResponseBinder(pub(crate) h2::server::ResponseIdentityBinder);
#[cfg(feature = "http2")]
impl ResponseBinder {
    /// Bind the application identity before publishing an admitted request.
    pub fn bind(&mut self, identity: ResponseIdentity) -> io::Result<()> {
        self.0
            .bind(identity.0.get())
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error))
    }
}
