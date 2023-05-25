use crate::{vote::Vote, Height};

/// A notification to be consumed by the reactor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Notification<H, Id, Sig> {
	/// Kill command.
	Kill,

	/// A validator was included
	NewValidator {
		/// Initial block height.
		height: Height,
		/// Validity period of the validator.
		validity: u64,
		/// Validator identifier.
		validator: Id,
	},

	/// A new vote was received
	Vote {
		/// Vote to be processed
		vote: Vote<H, Id, Sig>,
	},

	/// A block was cleared for consensus.
	///
	/// The reactor will expect this event before it can upgrade from the Propose phase.
	BlockAuthorized {
		/// Block height
		height: Height,
		/// Block identifier.
		block_id: H,
	},

	/// A block was generated and is available in the network so the reactor can initiate the
	/// propose protocol.
	BlockProposeAuthorized {
		/// Block height
		height: Height,
		/// Block identifier.
		block_id: H,
	},
}
