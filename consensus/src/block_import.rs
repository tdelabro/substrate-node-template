use std::sync::Arc;

use sc_consensus::{
	block_import::BlockImport, BlockCheckParams, BlockImportParams, ImportResult,
	JustificationImport,
};
use sp_api::{NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_consensus::Error as ConsensusError;
use sp_runtime::{traits::Block as BlockT, Justification};

#[derive(Debug)]
pub struct TendermintBlockImport<C> {
	inner: Arc<C>,
}

impl<C> Clone for TendermintBlockImport<C> {
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone() }
	}
}

impl<C> TendermintBlockImport<C> {
	pub fn new(client: Arc<C>) -> Self {
		Self { inner: client }
	}
}

#[async_trait::async_trait]
impl<B, C> BlockImport<B> for TendermintBlockImport<C>
where
	B: BlockT,
	for<'a> &'a C: BlockImport<B, Error = ConsensusError, Transaction = TransactionFor<C, B>>,
	TransactionFor<C, B>: 'static,
	C: ProvideRuntimeApi<B> + Send + Sync + 'static,
{
	type Error = ConsensusError;
	type Transaction = sp_api::TransactionFor<C, B>;

	/// Check block preconditions.
	async fn check_block(
		&mut self,
		block: BlockCheckParams<B>,
	) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).await.map_err(Into::into)
	}

	/// Import a block.
	async fn import_block(
		&mut self,
		block: BlockImportParams<B, Self::Transaction>,
	) -> Result<ImportResult, Self::Error> {
		self.inner.import_block(block).await.map_err(Into::into)
	}
}

#[async_trait::async_trait]
impl<B, C> JustificationImport<B> for TendermintBlockImport<C>
where
	B: BlockT,
	C: Send + Sync,
{
	type Error = ConsensusError;

	async fn on_start(&mut self) -> Vec<(B::Hash, NumberFor<B>)> {
		Vec::new()
	}

	async fn import_justification(
		&mut self,
		hash: B::Hash,
		number: NumberFor<B>,
		justification: Justification,
	) -> Result<(), Self::Error> {
		Ok(())
	}
}
