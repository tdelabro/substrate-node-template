use std::{sync::Arc, thread, time::Duration};

use assert_matches::assert_matches;
use sc_keystore::LocalKeystore;
use sp_core::sr25519;
use sp_keystore::SyncCryptoStore;
use tendermint_reactor::{
	config::Config,
	keychain::{KeyChain, Keychain},
	message::{Event, Message, Notification, Request, Response},
	step::Step,
	tokio_reactor::TokioReactor,
	vote::Vote,
};

type Reactor = TokioReactor<[u8; 32], sr25519::Public, sr25519::Signature>;
type KeyStore = Arc<KeyChain<sr25519::Public, LocalKeystore>>;

async fn add_validators(
	reactor: &mut Reactor,
	height: u64,
	validity: u64,
	validators: impl Iterator<Item = sr25519::Public>,
) {
	for validator in validators {
		reactor
			.notify(Notification::NewValidator { height, validity, validator })
			.await
			.expect("notification failed");
	}
}

async fn init_reactor(reactor: &mut Reactor, id: u64, start: u64, validity: u64) {
	let response = reactor
		.request(Request::Initialize { id, start, validity })
		.await
		.expect("failed to initialize the reactor");
	assert_matches!(response, Response::Initialize { initialized, .. } if initialized);
}

async fn get_round_and_leader(
	reactor: &mut Reactor,
	id: u64,
	current_height: u64,
) -> (u64, sr25519::Public) {
	let response = reactor.request(Request::Round { id }).await.expect("failed to query the round");

	match response {
		Response::Round { height, round, leader, .. } if height == current_height =>
			(round, leader.expect("Sould return a leader")),
		_ => panic!("unexpected height"),
	}
}

async fn wait_until_reactor_ready_to_recieve_propose(
	reactor: &mut Reactor,
	current_height: u64,
	current_round: u64,
) -> bool {
	println!("wait reactor is ready");
	loop {
		match async_std::future::timeout(Duration::from_millis(50), reactor.next_async()).await {
			Ok(Some(Message::Event(Event::AwaitingBlock { height })))
				if height == current_height =>
				break,
			Err(_) => {
				let (round, _) = get_round_and_leader(reactor, 100, current_height).await;
				if round != current_round {
					return false
				}
			},
			_ => (),
		}
	}

	true
}

async fn notify_block_propose_authorized(
	reactor: &mut Reactor,
	current_height: u64,
	block_id: [u8; 32],
) {
	reactor
		.notify(Notification::BlockProposeAuthorized { height: current_height, block_id })
		.await
		.expect("failed to notify");
}

fn find_leader_keystore<'a>(
	mut validators: impl Iterator<
		Item = &'a (Arc<KeyChain<sr25519::Public, LocalKeystore>>, sr25519::Public),
	>,
	leader: &sr25519::Public,
) -> KeyStore {
	validators
		.find_map(|(k, p)| (p == leader).then(|| k.clone()))
		.expect("failed to fetch leader validator keychain")
}

fn find_other_validator_keystore<'a>(
	mut validators: impl Iterator<
		Item = &'a (Arc<KeyChain<sr25519::Public, LocalKeystore>>, sr25519::Public),
	>,
	leader: &sr25519::Public,
) -> KeyStore {
	validators
		.find_map(|(k, p)| (p != leader).then(|| k.clone()))
		.expect("failed to fetch other validator keychain")
}

async fn submit_commit_vote(
	reactor: &mut Reactor,
	keystore: KeyStore,
	current_height: u64,
	current_round: u64,
	block_id: [u8; 32],
) {
	let propose = Vote::signed::<_, sr25519::Pair>(
		keystore.clone(),
		current_height,
		current_round,
		block_id,
		Step::Commit,
	)
	.expect("failed to create vote");

	reactor
		.notify(Notification::Vote { vote: propose })
		.await
		.expect("failed to notify reactor");
}

async fn submit_propose_vote(
	reactor: &mut Reactor,
	keystore: KeyStore,
	current_height: u64,
	current_round: u64,
	block_id: [u8; 32],
) {
	let propose = Vote::signed::<_, sr25519::Pair>(
		keystore.clone(),
		current_height,
		current_round,
		block_id,
		Step::Propose,
	)
	.expect("failed to create vote");

	reactor
		.notify(Notification::Vote { vote: propose })
		.await
		.expect("failed to notify reactor");
}

async fn submit_prevote_vote(
	reactor: &mut Reactor,
	keystore: KeyStore,
	current_height: u64,
	current_round: u64,
	block_id: [u8; 32],
) {
	let prevote = Vote::signed::<_, sr25519::Pair>(
		keystore.clone(),
		current_height,
		current_round,
		block_id,
		Step::Prevote,
	)
	.expect("failed to create vote");

	reactor
		.notify(Notification::Vote { vote: prevote })
		.await
		.expect("failed to notify reactor");
}

async fn submit_precommit_vote(
	reactor: &mut Reactor,
	keystore: KeyStore,
	current_height: u64,
	current_round: u64,
	block_id: [u8; 32],
) {
	let precommit = Vote::signed::<_, sr25519::Pair>(
		keystore.clone(),
		current_height,
		current_round,
		block_id,
		Step::Precommit,
	)
	.expect("failed to create vote");

	reactor
		.notify(Notification::Vote { vote: precommit })
		.await
		.expect("failed to notify reactor");
}

async fn check_state_not_updated(reactor: &mut Reactor, current_height: u64, current_round: u64) {
	println!("check no change");
	// Reactor should not update state until block is authorized
	let response = reactor
		.request(Request::Round { id: 4 })
		.await
		.expect("failed to query the round");

	match response {
		Response::Round { height, round, step, .. }
			if height == current_height &&
				round == current_round &&
				(step.is_none() || step == Some(Step::NewRound)) =>
			(),
		_ => panic!("unexpected step"),
	};
}

async fn wait_step_is_precommit(
	reactor: &mut Reactor,
	current_height: u64,
	current_round: u64,
) -> bool {
	// Reactor should be precommit after prevote is done
	println!("wait is precommit");
	loop {
		let response = reactor
			.request(Request::Round { id: 5 })
			.await
			.expect("failed to query the round");

		match response {
			Response::Round { height, .. } if height != current_height => panic!("invalid height"),
			Response::Round { round, .. } if round != current_round => return false,
			Response::Round { step: Some(Step::Precommit), .. } => break,
			_ => (),
		};
	}

	println!("Precommit");
	true
}

async fn authorize_block(reactor: &mut Reactor, current_height: u64, block_id: [u8; 32]) {
	// Authorize the block
	reactor
		.notify(Notification::BlockAuthorized { height: current_height, block_id })
		.await
		.expect("notification failed");
}

async fn wait_until_round_step_is_prevote(
	reactor: &mut Reactor,
	current_height: u64,
	current_round: u64,
) -> bool {
	println!("wait is prevote");
	// Authorized block should move to prevote
	loop {
		let response = reactor
			.request(Request::Round { id: 4 })
			.await
			.expect("failed to query the round");

		match response {
			Response::Round { height, .. } if height != current_height => panic!("invalid height"),
			Response::Round { round, .. } if round != current_round => return false,
			Response::Round { step: Some(Step::Prevote), .. } => break,
			_ => (),
		};
	}

	println!("Prevote");
	true
}

async fn wait_until_round_changed(reactor: &mut Reactor, current_height: u64, current_round: u64) {
	let d = Duration::from_millis(100);
	loop {
		let (round, _) = get_round_and_leader(reactor, 2, current_height).await;
		if round != current_round {
			break
		}
	}
}

#[tokio::test]
async fn consensus() {
	let validators = 4;

	let mut validators: Vec<(Arc<KeyChain<sr25519::Public, LocalKeystore>>, sr25519::Public)> =
		(0..validators)
			.map(|_| {
				let local_keystore: Arc<LocalKeystore> = Arc::new(LocalKeystore::in_memory());
				let mut keychain = KeyChain::new(local_keystore);
				let key_type_id = <KeyChain<sr25519::Public, LocalKeystore> as Keychain<
					_,
					_,
					sr25519::Pair,
				>>::KEY_TYPE_ID;

				let public = keychain.sr25519_generate_new(key_type_id, None).unwrap();

				let keys = <KeyChain<sr25519::Public, LocalKeystore> as Keychain<
					_,
					_,
					sr25519::Pair,
				>>::keystore(&keychain)
				.sr25519_public_keys(key_type_id);
				assert_eq![keys, vec![public]];

				(Arc::new(keychain), public)
			})
			.collect();

	let config = Config::default();
	let node_owner = validators.pop().unwrap();
	let mut reactor = TokioReactor::<[u8; 32], sr25519::Public, sr25519::Signature>::spawn::<
		LocalKeystore,
		sr25519::Pair,
	>(config, node_owner.0);

	// Query the public identity for the initial height
	let public = reactor
		.request(Request::Identity { id: 0, height: 0 })
		.await
		.expect("Failed to request node identity from the reactor");

	let public = match public {
		Response::Identity { public, .. } => public,
		_ => panic!("unexpected response"),
	}
	.expect("The identity of the reactor should be available");

	// Add all validators of the network
	add_validators(&mut reactor, 0, 100, validators.iter().map(|t| t.1)).await;

	// init the reactor
	init_reactor(&mut reactor, 1, 0, 100).await;

	let mut current_height = 0;

	loop {
		let (round, leader) = get_round_and_leader(&mut reactor, 2, current_height).await;
		let block_id = [current_height as u8; 32];
		println!("h{current_height}-r{round}");

		let mut commit_found = false;
		let mut event_found = false;

		if leader == public {
			println!("Leader is public");
			let mut propose_found = false;

			// Expect reactor to request block propose authorization
			if !wait_until_reactor_ready_to_recieve_propose(
				&mut reactor,
				current_height,
				current_height,
			)
			.await
			{
				println!("we skip next");
				continue
			};
			println!("reactor is ready");

			// propose
			notify_block_propose_authorized(&mut reactor, current_height, block_id).await;

			// Block authorized, expecting propose and commit
			while let Some(m) = reactor.next_async().await {
				match m {
					Message::Event(Event::Broadcast { vote })
						if vote.height() == current_height &&
							vote.round() == round && vote.step() == Step::Propose &&
							vote.validator() == &public && vote.block_id() == &block_id =>
					{
						propose_found = true;
					},
					Message::Event(Event::Broadcast { vote })
						if vote.height() == current_height &&
							vote.round() == round && vote.step() == Step::Commit &&
							vote.validator() == &public && vote.block_id() == &block_id =>
					{
						commit_found = true;
					},
					Message::Event(Event::Commit {
						height,
						round: _round,
						block_id: _block_id,
					}) if height == current_height && round == _round && _block_id == block_id => {
						event_found = true;
					},
					_ => (),
				}

				if propose_found && commit_found && event_found {
					break
				}
			}
		} else {
			println!("Leader is NOT public");
			let keystore = find_leader_keystore(validators.iter(), &leader);

			submit_propose_vote(&mut reactor, keystore.clone(), current_height, round, block_id)
				.await;
			// check_state_not_updated(&mut reactor, current_height, round).await;
			authorize_block(&mut reactor, current_height, block_id).await;
			if !wait_until_round_step_is_prevote(&mut reactor, current_height, round).await {
				continue
			};

			// One peer prevote should be enough since proposer is `commit` and node is `prevote`
			// This is BFT consensus for 4 validators
			let other_validator = find_other_validator_keystore(validators.iter(), &leader);
			submit_prevote_vote(&mut reactor, other_validator, current_height, round, block_id)
				.await;

			// Reactor should be precommit after prevote is done
			if !wait_step_is_precommit(&mut reactor, current_height, round).await {
				continue
			};

			// One precommit vote should be enough to commit BFT

			submit_precommit_vote(&mut reactor, keystore, current_height, round, block_id).await;
			if !wait_for_commit(&mut reactor, current_height, round, block_id, public).await {
				continue
			};
		}

		current_height += 1;
	}
}

async fn wait_for_commit(
	reactor: &mut Reactor,
	current_height: u64,
	current_round: u64,
	current_block_id: [u8; 32],
	public: sr25519::Public,
) -> bool {
	println!("wait for commit");
	let mut commit_found = false;
	let mut event_found = false;

	while let Some(m) = reactor.next_async().await {
		match m {
			Message::Event(Event::Broadcast { vote })
				if vote.height() == current_height &&
					vote.round() == current_round &&
					vote.step() == Step::Commit &&
					vote.validator() == &public &&
					vote.block_id() == &current_block_id =>
			{
				commit_found = true;
			},
			Message::Event(Event::Commit { height, round, block_id })
				if height == current_height &&
					round == current_round &&
					block_id == current_block_id =>
			{
				event_found = true;
			},
			Message::Event(Event::AwaitingBlock { .. }) => return false,
			_ => (),
		}

		if commit_found && event_found {
			break
		}
	}
	println!("Commit");
	true
}
