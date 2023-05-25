use std::{collections::BTreeMap, fmt::Debug};

use sp_core::{Pair, Public};

use super::{error::Error, keychain::Keychain, step::Step, vote::Vote, Height, Round};

pub type Validators<Id> = BTreeMap<Id, (Height, Height)>;

#[derive(Debug, Clone)]
pub struct Metadata<H, Id> {
	committed_height: Height,
	committed_rounds: u64,

	/// Set of authorized blocks for commit
	authorized_blocks: BTreeMap<H, Height>,
	/// Blocks authorized for the propose protocol.
	propose_blocks: BTreeMap<Height, H>,
	/// key -> (from, to) inclusive height range
	validators: Validators<Id>,
	/// (height, round, key) -> step
	step: BTreeMap<(Height, Round, Id), Step>,
}

impl<H, Id> Default for Metadata<H, Id> {
	fn default() -> Self {
		let committed_height = Self::HEIGHT_NEVER;
		let committed_rounds = 0;

		let authorized_blocks = Default::default();
		let propose_blocks = Default::default();
		let step = Default::default();
		let validators = Default::default();

		Self {
			authorized_blocks,
			committed_height,
			committed_rounds,
			propose_blocks,
			validators,
			step,
		}
	}
}

impl<H, Id> Metadata<H, Id> {
	/// Height representing a `never` step
	pub const HEIGHT_NEVER: Height = Height::MAX;
}

impl<H, Id> Metadata<H, Id>
where
	Id: Debug + Public + Ord,
	H: Clone + Ord + AsRef<[u8]>,
{
	pub fn add_validator(&mut self, validator: Id, height: Height, validity: u64) {
		let validity = height + validity;

		match self.validators.get_mut(&validator) {
			Some((from, to)) => {
				*from = height;
				*to = validity;
			},

			None => {
				self.validators.insert(validator, (height, validity));
			},
		}
	}

	/// Authorize the provided block in the given height
	pub fn authorize_block(&mut self, block_id: H, height: Height) {
		if self.committed_height.wrapping_add(1) <= height {
			self.authorized_blocks.insert(block_id, height);
		}
	}

	/// Authorize the propose protocol for the given height.
	pub fn authorize_block_propose(&mut self, height: Height, block_id: H) {
		if self.committed_height.wrapping_add(1) <= height {
			self.propose_blocks.insert(height, block_id);
		}
	}

	/// Block height of the last commit
	pub const fn committed_height(&self) -> Height {
		self.committed_height
	}

	/// Total committed rounds
	pub const fn committed_rounds(&self) -> u64 {
		self.committed_rounds
	}

	/// Sorted validators filtered per height.
	pub fn validators_at_height(&self, height: Height) -> impl Iterator<Item = &Id> {
		self.validators
			.iter()
			.filter_map(move |(k, (from, to))| (*from <= height && height <= *to).then(|| k))
	}

	/// Validators count per height.
	pub fn validators_at_height_count(&self, height: Height) -> usize {
		self.validators_at_height(height).count()
	}

	/// Return the authorized block for propose for the given height, if present
	pub fn authorized_propose(&self, height: Height) -> Option<&H> {
		self.propose_blocks.get(&height)
	}

	/// Fetch the current step of a validator for a given round
	pub fn validator_step(&self, height: Height, round: Round, key: Id) -> Option<Step> {
		self.step.get(&(height, round, key)).copied()
	}

	/// Check if the block is authorized for the given height
	pub fn is_block_authorized(&self, block_id: &H, height: Height) -> bool {
		self.authorized_blocks.get(block_id).filter(|&&h| h == height).is_some()
	}

	/// Step count for a given round
	pub fn step_count(&self, height: Height, round: Round, step: Step) -> usize {
		self.step
			.iter()
			.filter(|((h, r, _), s)| h == &height && r == &round && s == &&step)
			.count()
	}

	/// Evaluate the step count for a given round, including the validators that are in subsequent
	/// steps.
	pub fn evaluate_step_count(&self, height: Height, round: Round, step: Step) -> usize {
		let current = self.step_count(height, round, step);

		// FIXME optimize
		let subsequent: usize = step.map(|s| self.step_count(height, round, s)).sum::<usize>();

		current + subsequent
	}

	/// Upgrade a validator step, returning true if there was a change
	pub fn upgrade_validator_step<Sig>(&mut self, vote: &Vote<H, Id, Sig>) -> bool
where {
		let height = vote.height();
		let round = vote.round();
		let validator = vote.validator();
		let step = vote.step();

		let updated = match self.step.get_mut(&(height, round, validator.clone())) {
			Some(s) if &step > s => {
				#[cfg(feature = "trace")]
				tracing::debug!(
					"upgrading step; validator: {:?}, height: {}, round: {}, step: {:?}",
					validator,
					height,
					round,
					step
				);

				*s = step;
				true
			},

			None => {
				#[cfg(feature = "trace")]
				tracing::debug!(
					"upgrading step; validator: {:?}, height: {}, round: {}, step: {:?}",
					validator,
					height,
					round,
					step
				);

				self.step.insert((height, round, validator.clone()), step);
				true
			},

			_ => {
				#[cfg(feature = "trace")]
				tracing::trace!(
					"upgrading step skipped; validator: {:?}, height: {}, round: {}, step: {:?}",
					validator,
					height,
					round,
					step
				);

				false
			},
		};

		updated
	}

	pub fn commit(&mut self, height: Height, round: Round) -> bool {
		// Commit only to the subsequent block
		if !self.committed_height.wrapping_add(1) == height {
			return false
		}

		// Remove all expired content
		self.authorized_blocks.retain(|_, h| height < *h);
		self.propose_blocks.retain(|h, _| height < *h);
		self.validators.retain(|_, &mut (_, to)| height < to);
		self.step.retain(|(h, _, _), _| height < *h);

		self.committed_rounds += 1 + round;
		self.committed_height = height;

		true
	}
	/// Validate a vote, checking if the author is a validator of the round, and if the signature is
	/// valid.
	pub fn validate<K, Sig, P>(&self, vote: &Vote<H, Id, Sig>) -> Result<(), Error>
	where
		K: Keychain<Id, Sig, P>,
		P: Pair<Public = Id, Signature = Sig>,
	{
		let height = vote.height();
		let validator = vote.validator();

		let is_height_validator = self.validators_at_height(height).any(|v| v == validator);
		if !is_height_validator {
			return Err(Error::ValidatorNotFound)
		}

		vote.validate::<K, P>().map_err(|_| Error::InvalidSignature)?;

		Ok(())
	}
}
