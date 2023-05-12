use std::marker::PhantomData;

use sc_consensus::{BlockImportParams, Verifier};
use sp_runtime::traits::Block as BlockT;

pub struct TendermintVerifier<B: BlockT> {
	_marker: PhantomData<B>,
}

impl<B: BlockT> TendermintVerifier<B> {
	pub fn new() -> Self {
		Self { _marker: PhantomData }
	}
}

#[async_trait::async_trait]
impl<B: BlockT> Verifier<B> for TendermintVerifier<B> {
	async fn verify(
		&mut self,
		mut block: BlockImportParams<B, ()>,
	) -> Result<BlockImportParams<B, ()>, String> {
		Ok(block)
	}
}
