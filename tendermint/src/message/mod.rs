mod event;
mod notification;
mod request;

pub use event::Event;
pub use notification::Notification;
pub use request::{Request, Response};

/// I/O interface with the reactor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Message<H, Id, Sig> {
	/// Event produced by the reactor
	Event(Event<H, Id, Sig>),
	/// Notification to be consumed by the reactor
	Notification(Notification<H, Id, Sig>),
	/// Request-response to be executed by the reactor
	Request(Request),
	/// Response generated from a request
	Response(Response<Id>),
}

impl<H, Id, Sig> From<Event<H, Id, Sig>> for Message<H, Id, Sig> {
	fn from(e: Event<H, Id, Sig>) -> Self {
		Self::Event(e)
	}
}

impl<H, Id, Sig> From<Notification<H, Id, Sig>> for Message<H, Id, Sig> {
	fn from(n: Notification<H, Id, Sig>) -> Self {
		Self::Notification(n)
	}
}

impl<H, Id, Sig> From<Request> for Message<H, Id, Sig> {
	fn from(r: Request) -> Self {
		Self::Request(r)
	}
}
