use async_trait::async_trait;
use time::OffsetDateTime;

use core::{fmt, time::Duration};
use std::{boxed::Box, fmt::Debug};

use super::message::Message;

/// Reactor I/O handler
#[async_trait]
pub trait Moderator<H, Id, Sig>: Send + Sync
where
	H: Send + Debug,
	Id: Send + Debug,
	Sig: Send + Debug,
{
	/// Concrete error of the trait.
	type Error: fmt::Display;

	/// Current timestamp in UTC
	fn now(&self) -> OffsetDateTime {
		OffsetDateTime::now_utc()
	}

	/// Messages consumed by the reactor
	async fn inbound(&mut self) -> Result<Option<Message<H, Id, Sig>>, Self::Error>;

	/// Messages consumed by the reactor - should block
	fn inbound_blocking(&mut self) -> Result<Option<Message<H, Id, Sig>>, Self::Error>;

	/// Messages dispatched from the reactor
	async fn outbound(
		&mut self,
		message: Message<H, Id, Sig>,
		timeout: Duration,
	) -> Result<(), Self::Error>;

	/// Messages consumed by the reactor that need to be rescheduled
	async fn rebound(
		&mut self,
		message: Message<H, Id, Sig>,
		timeout: Duration,
	) -> Result<(), Self::Error>;

	/// Send a message from the reactor.
	async fn send(&mut self, message: Message<H, Id, Sig>, timeout: Duration)
	where
		H: 'async_trait,
		Sig: 'async_trait,
		Id: 'async_trait,
	{
		#[cfg(feature = "trace")]
		tracing::debug!("sending message {:?}", message);

		if let Err(_e) = self.outbound(message, timeout).await {
			#[cfg(feature = "trace")]
			tracing::error!("error sending outbound message: {}", _e);
		}
	}

	/// Requeue a message that cannot be consumed by the reactor.
	async fn requeue(&mut self, message: Message<H, Id, Sig>, timeout: Duration)
	where
		H: 'async_trait,
		Sig: 'async_trait,
		Id: 'async_trait,
	{
		if let Err(_e) = self.rebound(message, timeout).await {
			#[cfg(feature = "trace")]
			tracing::error!("error rebounding message: {}", _e);
		}
	}
}
