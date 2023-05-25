use std::{collections::HashMap, ops::Range, sync::Arc};

use sp_application_crypto::KeyTypeId;
use sp_core::{sr25519, Pair, Public};
use sp_keystore::SyncCryptoStore;

use super::Height;

#[cfg(feature = "memory")]
pub mod memory;

/// Keychain provider for the protocol.
pub trait Keychain<Id: Public, Sig, P: Pair<Public = Id, Signature = Sig>> {
	type Keystore: SyncCryptoStore;
	const KEY_TYPE_ID: KeyTypeId;

	/// Fetch the public key of the node for the given round
	fn public(&self, height: &Height) -> Option<&Id>;

	fn keystore(&self) -> &Self::Keystore;

	/// Sign the result of a given digest
	fn sign(&self, height: &Height, data: &[u8]) -> Option<Sig>
	where
		for<'a> Sig: TryFrom<&'a [u8]>,
	{
		let public = self.public(height)?;

		let public_type_pair = public.to_public_crypto_pair();

		let res =
			SyncCryptoStore::sign_with(self.keystore(), Self::KEY_TYPE_ID, &public_type_pair, data);

		res.ok()?.map(|s| Sig::try_from(s.as_slice()).ok()).flatten()
	}

	/// Verify the signature against the result of a given digest
	fn verify(signature: &Sig, author: &Id, digest: &[u8]) -> bool {
		P::verify(signature, digest, author)
	}
}

#[derive(Clone)]
pub struct KeyChain<Id, K: SyncCryptoStore> {
	authorities: HashMap<Range<Height>, Id>,
	keystore: Arc<K>,
}

impl<Id, K> KeyChain<Id, K>
where
	K: SyncCryptoStore,
{
	pub fn new(keystore: Arc<K>) -> Self {
		Self { authorities: Default::default(), keystore }
	}
}

impl<K> KeyChain<sr25519::Public, K>
where
	K: SyncCryptoStore,
{
	pub fn sr25519_generate_new(
		&mut self,
		id: KeyTypeId,
		seed: Option<&str>,
	) -> Result<sr25519::Public, sp_keystore::Error> {
		let public = SyncCryptoStore::sr25519_generate_new(&*self.keystore, id, seed)?;

		_ = self.authorities.insert(Range { start: Height::MIN, end: Height::MAX }, public);

		Ok(public)
	}
}

impl<Id, Sig, P, K> Keychain<Id, Sig, P> for KeyChain<Id, K>
where
	Id: Public,
	P: Pair<Public = Id, Signature = Sig>,
	K: sp_keystore::SyncCryptoStore,
{
	type Keystore = K;
	const KEY_TYPE_ID: KeyTypeId = KeyTypeId(*b"tend");

	fn public(&self, height: &Height) -> Option<&Id> {
		self.authorities
			.iter()
			.find_map(|(range, id)| range.contains(height).then(|| id))
	}

	fn keystore(&self) -> &Self::Keystore {
		&self.keystore
	}
}

#[cfg(test)]
mod tests {
	use sc_keystore::LocalKeystore;

	use super::*;

	#[test]
	fn key_creation() {
		let keystore_path = tempfile::tempdir().expect("Creates keystore path");
		let local_keystore: Arc<LocalKeystore> =
			Arc::new(LocalKeystore::open(keystore_path.path(), None).expect("Creates keystore"));
		let mut keychain = KeyChain::<sr25519::Public, LocalKeystore>::new(local_keystore);

		let key_type_id = <KeyChain<sr25519::Public, LocalKeystore> as Keychain<
			_,
			_,
			sr25519::Pair,
		>>::KEY_TYPE_ID;

		let public = keychain.sr25519_generate_new(key_type_id, None).unwrap();

		let keys =
			<KeyChain<sr25519::Public, LocalKeystore> as Keychain<_, _, sr25519::Pair>>::keystore(
				&keychain,
			)
			.sr25519_public_keys(key_type_id);

		assert_eq!(keys, vec![public]);
	}
}
