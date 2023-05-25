use async_trait::async_trait;
use sp_core::{Pair, Public};
use tokio::sync::mpsc;

use core::time::Duration;
use std::{fmt::Debug, sync::Arc, time::Instant};

use super::{
	config::Config,
	error::Error,
	keychain::{KeyChain, Keychain},
	message::{Message, Notification, Request, Response},
	moderator::Moderator,
	state::State,
};

/// Communication bridge with a consensus reactor.
pub struct TokioReactor<H, Id, Sig> {
	timeout: Duration,

	listener: mpsc::Receiver<Message<H, Id, Sig>>,
	sender: mpsc::Sender<Message<H, Id, Sig>>,

	/// Reactor will dispatch messages to
	outbound: mpsc::Sender<Message<H, Id, Sig>>,
}

impl<H, Id, Sig> TokioReactor<H, Id, Sig>
where
	H: Clone + Default + Ord + AsRef<[u8]> + Send + Sync + 'static + Debug,
	Id: Public + Ord + Debug + 'static + Clone,
	Sig: Send + Debug + Clone,
{
	/// Await for the next message sent from a reactor
	pub async fn next_async(&mut self) -> Option<Message<H, Id, Sig>> {
		self.listener.recv().await
	}

	/// Send a notification to the reactor
	pub async fn notify(&mut self, notification: Notification<H, Id, Sig>) -> Result<(), Error> {
		let notification = Message::Notification(notification);

		self.sender
			.send_timeout(notification, self.timeout)
			.await
			.map_err(|_| Error::ResourceNotAvailable)
	}

	/// Send a request to the reactor
	pub async fn request(&mut self, request: Request) -> Result<Response<Id>, Error> {
		let id = request.id();
		let request = Message::Request(request);

		self.sender
			.send_timeout(request.clone(), self.timeout)
			.await
			.map_err(|_| Error::ResourceNotAvailable)?;

		#[cfg(feature = "trace")]
		tracing::debug!(
			"request {:?} sent, awaiting response with timeout {:?}",
			request,
			self.timeout
		);

		tokio::time::timeout(self.timeout, self._request(id))
			.await
			.map_err(|_e| Error::ResourceNotAvailable)?
	}

	async fn _request(&mut self, id: u64) -> Result<Response<Id>, Error> {
		loop {
			match self.listener.recv().await {
				Some(Message::Response(r)) if r.id() == id => return Ok(r),
				Some(m) =>
					if let Err(_e) = self.outbound.send(m.clone()).await {
						#[cfg(feature = "trace")]
						tracing::error!(
							"message {:?} discarded; outbound resource exhausted: {}",
							m,
							_e
						);

						return Err(Error::ResourceNotAvailable)
					},
				None => {
					#[cfg(feature = "trace")]
					tracing::trace!("attempting to receive request {}", id);
				},
			}
		}
	}

	/// Spawn a consensus reactor into a new thread. This struct will communicate with the spawned
	/// reactor.
	pub fn spawn<K, P>(config: Config, keystore: Arc<KeyChain<Id, K>>) -> Self
	where
		P: Pair<Public = Id, Signature = Sig>,
		Sig: for<'a> TryFrom<&'a [u8]> + 'static,
		K: sp_keystore::SyncCryptoStore + 'static,
		KeyChain<Id, K>: Keychain<Id, Sig, P>,
	{
		let Config { heartbeat, .. } = config;

		let (mut moderator, bridge) = TokioModerator::new(config);

		tokio::spawn(async move {
			let mut reactor = State::new(config);

			loop {
				let start = Instant::now();

				if let Err(_e) =
					reactor.heartbeat::<_, _, Sig, P>(keystore.clone(), &mut moderator).await
				{
					#[cfg(feature = "trace")]
					tracing::trace!("heartbeat error: {}", _e);
				}

				if reactor.should_quit() {
					break
				}

				let elapsed = start.elapsed().as_millis();
				let interval = heartbeat.saturating_sub(elapsed);
				let interval = std::time::Duration::from_millis(interval as u64);

				tokio::time::sleep(interval).await;
			}
		});

		bridge
	}
}

impl<H, Id, Sig> Iterator for TokioReactor<H, Id, Sig> {
	type Item = Message<H, Id, Sig>;

	fn next(&mut self) -> Option<Self::Item> {
		self.listener.try_recv().ok()
	}
}

struct TokioModerator<H, Id, Sig> {
	/// Reactor will consume messages from
	inbound: mpsc::Receiver<Message<H, Id, Sig>>,

	/// Reactor will dispatch messages to
	outbound: mpsc::Sender<Message<H, Id, Sig>>,

	/// Reactor will requeue its messages through
	rebound: mpsc::Sender<Message<H, Id, Sig>>,
}

impl<H, Id, Sig> TokioModerator<H, Id, Sig> {
	pub fn new(config: Config) -> (Self, TokioReactor<H, Id, Sig>) {
		let Config { capacity, timeout, .. } = config;

		let (rebound, inbound) = mpsc::channel(capacity);
		let (outbound, listener) = mpsc::channel(capacity);

		let sender = rebound.clone();
		let bridge = TokioReactor { timeout, listener, sender, outbound: outbound.clone() };

		let moderator = Self { inbound, outbound, rebound };

		(moderator, bridge)
	}
}

#[async_trait]
impl<H, Id, Sig> Moderator<H, Id, Sig> for TokioModerator<H, Id, Sig>
where
	H: Send + Debug,
	Id: Send + Debug,
	Sig: Send + Debug,
{
	type Error = Error;

	async fn inbound(&mut self) -> Result<Option<Message<H, Id, Sig>>, Self::Error> {
		Ok(self.inbound.try_recv().ok())
	}

	fn inbound_blocking(&mut self) -> Result<Option<Message<H, Id, Sig>>, Self::Error> {
		Ok(self.inbound.blocking_recv())
	}

	async fn outbound(
		&mut self,
		message: Message<H, Id, Sig>,
		timeout: Duration,
	) -> Result<(), Self::Error> {
		self.outbound
			.send_timeout(message, timeout)
			.await
			.map_err(|_| Error::ResourceNotAvailable)
	}

	async fn rebound(
		&mut self,
		message: Message<H, Id, Sig>,
		timeout: Duration,
	) -> Result<(), Self::Error> {
		self.rebound
			.send_timeout(message, timeout)
			.await
			.map_err(|_| Error::ResourceNotAvailable)
	}
}
