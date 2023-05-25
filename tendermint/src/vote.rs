use std::sync::Arc;

use sp_core::{Blake2Hasher, Hasher as H256Hasher, Pair, Public, H256};

use super::{error::Error, keychain::Keychain, step::Step, Height, Round};

/// A vote from a validator.
///
/// These votes are consumed to produce state change in the reactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vote<H, Id, Sig> {
	block_id: H,
	height: Height,
	round: Round,
	signature: Sig,
	step: Step,
	validator: Id,
}

impl<H, Id, Sig> Vote<H, Id, Sig>
where
	H: Clone + AsRef<[u8]>,
	Id: Public,
{
	/// Create a new vote from a given signature
	pub const fn new(
		validator: Id,
		signature: Sig,
		height: Height,
		round: Round,
		block_id: H,
		step: Step,
	) -> Self {
		Self { block_id, height, round, signature, step, validator }
	}

	/// Block Id of the step
	pub const fn block_id(&self) -> &H {
		&self.block_id
	}

	/// Target block height.
	pub const fn height(&self) -> Height {
		self.height
	}

	/// Target height round.
	pub const fn round(&self) -> Round {
		self.round
	}

	/// Signature provided by the owner of the vote
	pub const fn signature(&self) -> &Sig {
		&self.signature
	}

	/// Proposed step
	pub const fn step(&self) -> Step {
		self.step
	}

	/// Network identification of the author
	pub const fn validator(&self) -> &Id {
		&self.validator
	}
	/// Produce a guaranteed correctness signed vote
	pub fn signed<K, P>(
		keychain: Arc<K>,
		height: Height,
		round: Round,
		block_id: H,
		step: Step,
	) -> Result<Self, Error>
	where
		K: Keychain<Id, Sig, P>,
		Sig: for<'a> TryFrom<&'a [u8]>,
		P: Pair<Public = Id, Signature = Sig>,
	{
		let digest = Self::_digest(height, round, block_id.clone(), step);

		let signature = Keychain::sign(&*keychain, &height, digest.as_bytes())
			.ok_or(Error::NotRoundValidator)?;

		let validator = Keychain::public(&*keychain, &height).ok_or(Error::NotRoundValidator)?;

		let vote = Self::new(validator.clone(), signature, height, round, block_id, step);

		Ok(vote)
	}

	fn _digest(height: Height, round: Round, block_id: H, step: Step) -> H256 {
		let mut data: Vec<u8> = Vec::new();
		data.extend_from_slice(&height.to_be_bytes());
		data.extend_from_slice(&round.to_be_bytes());
		data.extend_from_slice(&block_id.as_ref());
		data.push(step as u8);
		Blake2Hasher::hash(&data)
	}

	/// Compute the digest of the vote. Will be used by the signature
	pub fn digest(&self) -> H256 {
		Self::_digest(self.height, self.round, self.block_id.clone(), self.step)
	}

	/// Validate the signature of the vote
	pub fn validate<K, P>(&self) -> Result<(), Error>
	where
		K: Keychain<Id, Sig, P>,
		P: Pair<Public = Id, Signature = Sig>,
	{
		let digest = self.digest();

		if K::verify(&self.signature, &self.validator, &digest.as_bytes()) {
			Ok(())
		} else {
			Err(Error::InvalidSignature)
		}
	}
}
