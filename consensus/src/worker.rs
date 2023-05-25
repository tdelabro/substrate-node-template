use std::{
	fmt::Debug,
	future::Future,
	hash::Hash,
	marker::PhantomData,
	pin::Pin,
	sync::Arc,
	time::{Duration, Instant},
};

use futures::prelude::*;

use codec::{Codec, Decode, Encode};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction};
use sc_consensus_aura::{AuraApi, CompatibleDigestItem};
use sc_consensus_slots::{
	InherentDataProviderExt, SimpleSlotWorker, SimpleSlotWorkerToSlotWorker, SlotInfo,
	SlotProportion, SlotResult, StorageChanges,
};
use sc_telemetry::{
	log::{debug, info, warn},
	telemetry, TelemetryHandle, CONSENSUS_DEBUG, CONSENSUS_INFO, CONSENSUS_WARN,
};
use sp_api::{HeaderT, ProvideRuntimeApi};
use sp_consensus::{BlockOrigin, Environment, Proposer, SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_core::{ByteArray, Pair, Public};
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::{
	app_crypto::{AppKey, AppPublic},
	traits::{Block as BlockT, Member, Zero},
	DigestItem,
};

use crate::TENDERMINT_ENGINE_ID;

pub struct TendermintWorker<C, E, I, L, P, SO> {
	client: Arc<C>,
	block_import: I,
	env: E,
	keystore: SyncCryptoStorePtr,
	sync_oracle: SO,
	justification_sync_link: L,
	force_authoring: bool,
	telemetry: Option<TelemetryHandle>,
	_key_type: PhantomData<P>,
}

type AuthorityId<P> = <P as Pair>::Public;

#[async_trait::async_trait]
impl<B, C, E, I, L, P, SO, Error, Transaction> SimpleSlotWorker<B>
	for TendermintWorker<C, E, I, L, P, SO>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + Send + Sync,
	I: BlockImport<B, Transaction = Transaction> + Send + Sync + 'static,
	SO: SyncOracle + Send + Sync,
	E: Environment<B, Error = Error> + Send + Sync,
	E::Proposer: Proposer<B, Error = Error, Transaction = Transaction>,
	Error: std::error::Error + Send + From<sp_consensus::Error> + 'static,
	L: sc_consensus::JustificationSyncLink<B>,
	P: Pair + Send + Sync,
	P::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	P::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
	Transaction: Send + 'static,
	C::Api: AuraApi<B, AuthorityId<P>>,
{
	type BlockImport = I;
	type SyncOracle = SO;
	type JustificationSyncLink = L;
	type CreateProposer =
		Pin<Box<dyn Future<Output = Result<E::Proposer, sp_consensus::Error>> + Send + 'static>>;
	type Proposer = E::Proposer;
	type Claim = P::Public;
	type AuxData = Vec<AuthorityId<P>>;

	fn logging_target(&self) -> &'static str {
		"tendermint"
	}

	fn block_import(&mut self) -> &mut Self::BlockImport {
		&mut self.block_import
	}

	fn aux_data(
		&self,
		header: &B::Header,
		slot: Slot,
	) -> Result<Self::AuxData, sp_consensus::Error> {
		let parent_hash = header.hash();
		let runtime_api = self.client.runtime_api();

		runtime_api
			.authorities(parent_hash)
			.ok()
			.ok_or(sp_consensus::Error::InvalidAuthoritiesSet)
	}

	fn authorities_len(&self, aux_data: &Self::AuxData) -> Option<usize> {
		Some(aux_data.len())
	}

	async fn claim_slot(
		&self,
		header: &B::Header,
		slot: Slot,
		aux_data: &Self::AuxData,
	) -> Option<Self::Claim> {
		let expected_author = slot_author::<P>(slot, aux_data);
		expected_author.and_then(|p| {
			if SyncCryptoStore::has_keys(
				&*self.keystore,
				&[(p.to_raw_vec(), sp_application_crypto::key_types::AURA)],
			) {
				Some(p.clone())
			} else {
				None
			}
		})
	}

	fn pre_digest_data(&self, slot: Slot, claim: &Self::Claim) -> Vec<sp_runtime::DigestItem> {
		vec![<DigestItem as CompatibleDigestItem<P::Signature>>::aura_pre_digest(slot)]
	}

	async fn block_import_params(
		&self,
		header: B::Header,
		header_hash: &B::Hash,
		body: Vec<B::Extrinsic>,
		storage_changes: StorageChanges<<Self::BlockImport as BlockImport<B>>::Transaction, B>,
		public: Self::Claim,
		epoch: Self::AuxData,
	) -> Result<
		sc_consensus::BlockImportParams<B, <Self::BlockImport as BlockImport<B>>::Transaction>,
		sp_consensus::Error,
	> {
		// sign the pre-sealed hash of the block and then
		// add it to a digest item.
		let public_type_pair = public.to_public_crypto_pair();
		let public = public.to_raw_vec();
		let signature = SyncCryptoStore::sign_with(
			&*self.keystore,
			<AuthorityId<P> as AppKey>::ID,
			&public_type_pair,
			header_hash.as_ref(),
		)
		.map_err(|e| sp_consensus::Error::CannotSign(public.clone(), e.to_string()))?
		.ok_or_else(|| {
			sp_consensus::Error::CannotSign(
				public.clone(),
				"Could not find key in keystore.".into(),
			)
		})?;
		let signature = signature
			.clone()
			.try_into()
			.map_err(|_| sp_consensus::Error::InvalidSignature(signature, public))?;

		let signature_digest_item =
			<DigestItem as CompatibleDigestItem<P::Signature>>::aura_seal(signature);

		let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
		import_block.post_digests.push(signature_digest_item);
		import_block.body = Some(body);
		import_block.state_action =
			StateAction::ApplyChanges(sc_consensus::StorageChanges::Changes(storage_changes));
		import_block.fork_choice = Some(ForkChoiceStrategy::LongestChain);

		Ok(import_block)
	}

	fn force_authoring(&self) -> bool {
		self.force_authoring
	}

	fn sync_oracle(&mut self) -> &mut Self::SyncOracle {
		&mut self.sync_oracle
	}

	fn justification_sync_link(&mut self) -> &mut Self::JustificationSyncLink {
		&mut self.justification_sync_link
	}

	fn proposer(&mut self, block: &B::Header) -> Self::CreateProposer {
		self.env
			.init(block)
			.map_err(|e| sp_consensus::Error::ClientImport(format!("{:?}", e)))
			.boxed()
	}

	fn telemetry(&self) -> Option<TelemetryHandle> {
		self.telemetry.clone()
	}

	fn proposing_remaining_duration(
		&self,
		slot_info: &sc_consensus_slots::SlotInfo<B>,
	) -> std::time::Duration {
		let parent_slot = find_pre_digest::<B, P::Signature>(&slot_info.chain_head).ok();

		sc_consensus_slots::proposing_remaining_duration(
			parent_slot,
			slot_info,
			&SlotProportion::new(2f32 / 3f32),
			None,
			sc_consensus_slots::SlotLenienceType::Exponential,
			self.logging_target(),
		)
	}

	/// Implements [`SlotWorker::on_slot`].
	async fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
	) -> Option<SlotResult<B, <Self::Proposer as Proposer<B>>::Proof>>
	where
		Self: Sync,
	{
		let slot = slot_info.slot;
		let telemetry = self.telemetry();
		let logging_target = self.logging_target();

		let proposing_remaining_duration = self.proposing_remaining_duration(&slot_info);

		let end_proposing_at = if proposing_remaining_duration == Duration::default() {
			debug!(
				target: logging_target,
				"Skipping proposal slot {} since there's no time left to propose", slot,
			);

			return None
		} else {
			Instant::now() + proposing_remaining_duration
		};

		let aux_data = match self.aux_data(&slot_info.chain_head, slot) {
			Ok(aux_data) => aux_data,
			Err(err) => {
				warn!(
					target: logging_target,
					"Unable to fetch auxiliary data for block {:?}: {}",
					slot_info.chain_head.hash(),
					err,
				);

				telemetry!(
					telemetry;
					CONSENSUS_WARN;
					"slots.unable_fetching_authorities";
					"slot" => ?slot_info.chain_head.hash(),
					"err" => ?err,
				);

				return None
			},
		};

		self.notify_slot(&slot_info.chain_head, slot, &aux_data);

		let authorities_len = self.authorities_len(&aux_data);

		if !self.force_authoring() &&
			self.sync_oracle().is_offline() &&
			authorities_len.map(|a| a > 1).unwrap_or(false)
		{
			debug!(target: logging_target, "Skipping proposal slot. Waiting for the network.");
			telemetry!(
				telemetry;
				CONSENSUS_DEBUG;
				"slots.skipping_proposal_slot";
				"authorities_len" => authorities_len,
			);

			return None
		}

		let claim = self.claim_slot(&slot_info.chain_head, slot, &aux_data).await?;

		if self.should_backoff(slot, &slot_info.chain_head) {
			return None
		}

		debug!(target: logging_target, "Starting authorship at slot: {slot}");

		telemetry!(telemetry; CONSENSUS_DEBUG; "slots.starting_authorship"; "slot_num" => slot);

		let proposer = match self.proposer(&slot_info.chain_head).await {
			Ok(p) => p,
			Err(err) => {
				warn!(target: logging_target, "Unable to author block in slot {slot:?}: {err}");

				telemetry!(
					telemetry;
					CONSENSUS_WARN;
					"slots.unable_authoring_block";
					"slot" => *slot,
					"err" => ?err
				);

				return None
			},
		};

		let proposal = self.propose(proposer, &claim, slot_info, end_proposing_at).await?;

		let (block, storage_proof) = (proposal.block, proposal.proof);
		let (header, body) = block.deconstruct();
		let header_num = *header.number();
		let header_hash = header.hash();
		let parent_hash = *header.parent_hash();


		// Here goes the round logic


		let block_import_params = match self
			.block_import_params(
				header,
				&header_hash,
				body.clone(),
				proposal.storage_changes,
				claim,
				aux_data,
			)
			.await
		{
			Ok(bi) => bi,
			Err(err) => {
				warn!(target: logging_target, "Failed to create block import params: {}", err);

				return None
			},
		};

		info!(
			target: logging_target,
			"🔖 Pre-sealed block for proposal at {}. Hash now {:?}, previously {:?}.",
			header_num,
			block_import_params.post_hash(),
			header_hash,
		);

		telemetry!(
			telemetry;
			CONSENSUS_INFO;
			"slots.pre_sealed_block";
			"header_num" => ?header_num,
			"hash_now" => ?block_import_params.post_hash(),
			"hash_previously" => ?header_hash,
		);

		let header = block_import_params.post_header();
		match self.block_import().import_block(block_import_params).await {
			Ok(res) => {
				res.handle_justification(
					&header.hash(),
					*header.number(),
					self.justification_sync_link(),
				);
			},
			Err(err) => {
				warn!(
					target: logging_target,
					"Error with block built on {:?}: {}", parent_hash, err,
				);

				telemetry!(
					telemetry;
					CONSENSUS_WARN;
					"slots.err_with_block_built_on";
					"hash" => ?parent_hash,
					"err" => ?err,
				);
			},
		}

		Some(SlotResult { block: B::new(header, body), storage_proof })
	}
}

/// Get slot author for given block along with authorities.
fn slot_author<P: Pair>(slot: Slot, authorities: &[AuthorityId<P>]) -> Option<&AuthorityId<P>> {
	if authorities.is_empty() {
		return None
	}

	let idx = *slot % (authorities.len() as u64);
	assert!(
		idx <= usize::MAX as u64,
		"It is impossible to have a vector with length beyond the address space; qed",
	);

	let current_author = authorities.get(idx as usize).expect(
		"authorities not empty; index constrained to list length;this is a valid index; qed",
	);

	Some(current_author)
}

/// Get pre-digests from the header
pub fn find_pre_digest<B: BlockT, Signature: Codec>(header: &B::Header) -> Result<Slot, String> {
	if header.number().is_zero() {
		return Ok(0.into())
	}

	let mut pre_digest: Option<Slot> = None;
	for log in header.digest().logs() {
		match (log.pre_runtime_try_to(&TENDERMINT_ENGINE_ID), pre_digest.is_some()) {
			(Some(_), true) => return Err("MultipleHeaders".to_string()),
			(None, _) => debug!("Ignoring digest not meant for us"),
			(s, false) => pre_digest = s,
		}
	}
	pre_digest.ok_or_else(|| "NoDigestFound".to_string())
}

pub fn start_tenderming<P, B, C, E, I, L, CIDP, SC, SO, Error, Transaction>(
	slot_duration: SlotDuration,
	select_chain: SC,
	create_inherent_data_providers: CIDP,
	client: Arc<C>,
	block_import: I,
	env: E,
	sync_oracle: SO,
	justification_sync_link: L,
	force_authoring: bool,
	keystore: SyncCryptoStorePtr,
	telemetry: Option<TelemetryHandle>,
) -> Result<impl Future<Output = ()>, sp_consensus::Error>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + Send + Sync,
	E: Environment<B, Error = Error> + Send + Sync + 'static,
	E::Proposer: Proposer<B, Error = Error, Transaction = Transaction>,
	I: BlockImport<B, Transaction = Transaction> + Send + Sync + 'static,
	L: sc_consensus::JustificationSyncLink<B>,
	P: Pair + Send + Sync,
	P::Public: AppPublic + Hash + Member + Encode + Decode,
	P::Signature: TryFrom<Vec<u8>> + Hash + Member + Encode + Decode,
	SC: SelectChain<B>,
	SO: SyncOracle + Send + Sync + Clone,
	CIDP: CreateInherentDataProviders<B, ()> + Send + 'static,
	CIDP::InherentDataProviders: InherentDataProviderExt + Send,
	Error: std::error::Error + Send + From<sp_consensus::Error> + 'static,
	Transaction: Send + 'static,
	C::Api: AuraApi<B, AuthorityId<P>>,
{
	let worker = TendermintWorker {
		client,
		block_import,
		keystore,
		env,
		sync_oracle: sync_oracle.clone(),
		justification_sync_link,
		force_authoring,
		telemetry,
		_key_type: PhantomData::<P>,
	};

	Ok(sc_consensus_slots::start_slot_worker(
		slot_duration,
		select_chain,
		SimpleSlotWorkerToSlotWorker(worker),
		sync_oracle,
		create_inherent_data_providers,
	))
}
