use prometheus::Registry;
use sc_consensus::{BasicQueue, BlockImport, BoxJustificationImport};
use sp_consensus::Error as ConsensusError;
use sp_runtime::traits::Block as BlockT;

use crate::verifier::TendermintVerifier;

pub type TendermintImportQueue<B, Transaction> = BasicQueue<B, Transaction>;

pub fn import_queue<B, I, Transaction>(
	block_import: I,
	justification_import: Option<BoxJustificationImport<B>>,
	spawner: &impl sp_core::traits::SpawnEssentialNamed,
	registry: Option<&Registry>,
) -> Result<TendermintImportQueue<B, Transaction>, sp_consensus::Error>
where
	B: BlockT,
	Transaction: Send + Sync + 'static,
	I: BlockImport<B, Error = ConsensusError, Transaction = Transaction> + Send + Sync + 'static,
{
	let verifier = TendermintVerifier::new();

	Ok(BasicQueue::new(verifier, Box::new(block_import), justification_import, spawner, registry))
}
