use std::{fmt::Debug, future::Future, hash::Hash, marker::PhantomData, pin::Pin, sync::Arc};

use futures::prelude::*;

use codec::{Codec, Decode, Encode};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction};
use sc_consensus_aura::{AuraApi, CompatibleDigestItem};
use sc_consensus_slots::{
	InherentDataProviderExt, SimpleSlotWorker, SimpleSlotWorkerToSlotWorker, SlotProportion,
	StorageChanges,
};
use sc_telemetry::{log::debug, TelemetryHandle};
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

use crate::{block_import, TENDERMINT_ENGINE_ID};

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
	SO: SyncOracle + Sync,
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
