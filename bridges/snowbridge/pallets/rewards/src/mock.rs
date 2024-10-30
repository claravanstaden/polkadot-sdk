// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use super::*;

use codec::Encode;
use frame_support::{derive_impl, parameter_types};
use hex_literal::hex;
use sp_core::{ConstU128, ConstU32, H160};
use sp_runtime::{
	traits::{IdentifyAccount, IdentityLookup, Verify},
	BuildStorage, MultiSignature,
};
use sp_std::{convert::From, default::Default};
use xcm::{latest::SendXcm, prelude::*};
use xcm_executor::AssetsInHolding;

use crate::{self as snowbridge_pallet_rewards};

pub type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system::{Pallet, Call, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		EthereumRewards: snowbridge_pallet_rewards::{Pallet, Call, Storage, Event<T>},
	}
);

pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

parameter_types! {
	pub const ExistentialDeposit: u128 = 1;
}

type Balance = u128;

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type Balance = Balance;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type AccountData = pallet_balances::AccountData<u128>;
	type Block = Block;
}


parameter_types! {
	pub EthereumNetwork: NetworkId = NetworkId::Ethereum { chain_id: 11155111 };
	pub WethAddress: H160 = hex!("774667629726ec1FaBEbCEc0D9139bD1C8f72a23").into();
}

impl snowbridge_pallet_rewards::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type AssetHubParaId = ConstU32<1000>;
	type EthereumNetwork = EthereumNetwork;
	type WethAddress = WethAddress;
	type XcmSender = MockXcmSender;
	type Token = Balances;
	type AssetTransactor = SuccessfulTransactor;
	type AssetHubXCMFee = ConstU128<1_000_000_000_000u128>;
	type WeightInfo = ();
}

// Mock XCM sender that always succeeds
pub struct MockXcmSender;

impl SendXcm for MockXcmSender {
	type Ticket = Xcm<()>;

	fn validate(
		dest: &mut Option<Location>,
		xcm: &mut Option<Xcm<()>>,
	) -> SendResult<Self::Ticket> {
		if let Some(location) = dest {
			match location.unpack() {
				(_, [Parachain(1001)]) => return Err(XcmpSendError::NotApplicable),
				_ => Ok((xcm.clone().unwrap(), Assets::default())),
			}
		} else {
			Ok((xcm.clone().unwrap(), Assets::default()))
		}
	}

	fn deliver(xcm: Self::Ticket) -> core::result::Result<XcmHash, XcmpSendError> {
		let hash = xcm.using_encoded(sp_io::hashing::blake2_256);
		Ok(hash)
	}
}

pub fn new_tester() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let ext = sp_io::TestExternalities::new(t);
	ext
}

pub struct SuccessfulTransactor;
impl TransactAsset for SuccessfulTransactor {
	fn can_check_in(_origin: &Location, _what: &Asset, _context: &XcmContext) -> XcmResult {
		Ok(())
	}

	fn can_check_out(_dest: &Location, _what: &Asset, _context: &XcmContext) -> XcmResult {
		Ok(())
	}

	fn deposit_asset(_what: &Asset, _who: &Location, _context: Option<&XcmContext>) -> XcmResult {
		Ok(())
	}

	fn withdraw_asset(
		_what: &Asset,
		_who: &Location,
		_context: Option<&XcmContext>,
	) -> Result<AssetsInHolding, XcmError> {
		Ok(AssetsInHolding::default())
	}

	fn internal_transfer_asset(
		_what: &Asset,
		_from: &Location,
		_to: &Location,
		_context: &XcmContext,
	) -> Result<AssetsInHolding, XcmError> {
		Ok(AssetsInHolding::default())
	}
}
