// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
//! Converts messages from Ethereum to XCM messages

use codec::{Decode, Encode};
use core::marker::PhantomData;
use frame_support::{traits::tokens::Balance as BalanceT, weights::Weight, PalletError};
use scale_info::TypeInfo;
use snowbridge_core::TokenId;
use sp_core::{Get, RuntimeDebug, H160, H256};
use sp_io::hashing::blake2_256;
use sp_runtime::{traits::MaybeEquivalence, MultiAddress};
use sp_std::prelude::*;
use xcm::prelude::{Junction::AccountKey20, *};
use xcm_executor::traits::ConvertLocation;

const MINIMUM_DEPOSIT: u128 = 1;

/// Messages from Ethereum are versioned. This is because in future,
/// we may want to evolve the protocol so that the ethereum side sends XCM messages directly.
/// Instead having BridgeHub transcode the messages into XCM.
#[derive(Clone, Encode, Decode, RuntimeDebug)]
pub enum VersionedMessage {
	V2(Message),
}

/// For V2, the ethereum side sends messages which are transcoded into XCM. These messages are
/// self-contained, in that they can be transcoded using only information in the message.
#[derive(Clone, Encode, Decode, RuntimeDebug)]
pub struct Message {
	/// The origin address
	pub origin: H160,
	/// The command originating from the Gateway contract
	pub xcm: Vec<u8>,
}

pub struct GlobalConsensusEthereumConvertsFor<AccountId>(PhantomData<AccountId>);
impl<AccountId> ConvertLocation<AccountId> for GlobalConsensusEthereumConvertsFor<AccountId>
where
	AccountId: From<[u8; 32]> + Clone,
{
	fn convert_location(location: &Location) -> Option<AccountId> {
		match location.unpack() {
			(_, [GlobalConsensus(Ethereum { chain_id })]) =>
				Some(Self::from_chain_id(chain_id).into()),
			_ => None,
		}
	}
}

impl<AccountId> GlobalConsensusEthereumConvertsFor<AccountId> {
	pub fn from_chain_id(chain_id: &u64) -> [u8; 32] {
		(b"ethereum-chain", chain_id).using_encoded(blake2_256)
	}
}

#[cfg(test)]
mod tests {
	use crate::inbound::{CallIndex, GlobalConsensusEthereumConvertsFor};
	use frame_support::{assert_ok, parameter_types};
	use hex_literal::hex;
	use xcm::prelude::*;
	use xcm_executor::traits::ConvertLocation;

	const NETWORK: NetworkId = Ethereum { chain_id: 11155111 };

	parameter_types! {
		pub EthereumNetwork: NetworkId = NETWORK;

		pub const CreateAssetCall: CallIndex = [1, 1];
		pub const CreateAssetExecutionFee: u128 = 123;
		pub const CreateAssetDeposit: u128 = 891;
		pub const SendTokenExecutionFee: u128 = 592;
	}

	#[test]
	fn test_contract_location_with_network_converts_successfully() {
		let expected_account: [u8; 32] =
			hex!("ce796ae65569a670d0c1cc1ac12515a3ce21b5fbf729d63d7b289baad070139d");
		let contract_location = Location::new(2, [GlobalConsensus(NETWORK)]);

		let account =
			GlobalConsensusEthereumConvertsFor::<[u8; 32]>::convert_location(&contract_location)
				.unwrap();

		assert_eq!(account, expected_account);
	}

	#[test]
	fn test_contract_location_with_incorrect_location_fails_convert() {
		let contract_location = Location::new(2, [GlobalConsensus(Polkadot), Parachain(1000)]);

		assert_eq!(
			GlobalConsensusEthereumConvertsFor::<[u8; 32]>::convert_location(&contract_location),
			None,
		);
	}

	#[test]
	fn test_reanchor_all_assets() {
		let ethereum_context: InteriorLocation = [GlobalConsensus(Ethereum { chain_id: 1 })].into();
		let ethereum = Location::new(2, ethereum_context.clone());
		let ah_context: InteriorLocation = [GlobalConsensus(Polkadot), Parachain(1000)].into();
		let global_ah = Location::new(1, ah_context.clone());
		let assets = vec![
			// DOT
			Location::new(1, []),
			// GLMR (Some Polkadot parachain currency)
			Location::new(1, [Parachain(2004)]),
			// AH asset
			Location::new(0, [PalletInstance(50), GeneralIndex(42)]),
			// KSM
			Location::new(2, [GlobalConsensus(Kusama)]),
			// KAR (Some Kusama parachain currency)
			Location::new(2, [GlobalConsensus(Kusama), Parachain(2000)]),
		];
		for asset in assets.iter() {
			// reanchor logic in pallet_xcm on AH
			let mut reanchored_asset = asset.clone();
			assert_ok!(reanchored_asset.reanchor(&ethereum, &ah_context));
			// reanchor back to original location in context of Ethereum
			let mut reanchored_asset_with_ethereum_context = reanchored_asset.clone();
			assert_ok!(
				reanchored_asset_with_ethereum_context.reanchor(&global_ah, &ethereum_context)
			);
			assert_eq!(reanchored_asset_with_ethereum_context, asset.clone());
		}
	}
}
