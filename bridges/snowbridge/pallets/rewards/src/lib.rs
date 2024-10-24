// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
#![cfg_attr(not(feature = "std"), no_std)]

pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

extern crate alloc;

use frame_support::{
	sp_runtime::{SaturatedConversion, Saturating},
	traits::fungible::{Inspect, Mutate},
	PalletError,
};
use frame_system::pallet_prelude::*;
pub use pallet::*;
use snowbridge_core::{rewards::RewardLedger, ParaId};
use sp_core::H160;
use sp_runtime::TokenError;
pub use weights::WeightInfo;
use xcm::prelude::{send_xcm, SendError as XcmpSendError, *};
use xcm_executor::traits::TransactAsset;
pub const LOG_TARGET: &str = "rewards";

pub type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
type BalanceOf<T> =
	<<T as pallet::Config>::Token as Inspect<<T as frame_system::Config>::AccountId>>::Balance;
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use sp_core::H256;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type AssetHubParaId: Get<u32>;
		type EthereumNetwork: Get<NetworkId>;
		type WethAddress: Get<H160>;
		/// XCM message sender
		type XcmSender: SendXcm;
		/// To withdraw and deposit an asset.
		type AssetTransactor: TransactAsset;
		/// Message relayers are rewarded with this asset
		type Token: Mutate<Self::AccountId> + Inspect<Self::AccountId>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A relayer reward was deposited
		RewardDeposited {
			/// The relayer account to which the reward was deposited.
			account_id: AccountIdOf<T>,
			/// The reward value.
			value: BalanceOf<T>,
		},
		RewardClaimed {
			/// The relayer account that claimed the reward.
			account_id: AccountIdOf<T>,
			/// The address that received the reward on AH.
			deposit_address: AccountIdOf<T>,
			/// The claimed reward value.
			value: BalanceOf<T>,
			/// The message ID that was provided, used to track the claim
			message_id: H256,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// XCMP send failure
		Send(SendError),
		/// The relayer rewards balance is lower than the claimed amount.
		InsufficientFunds,
		InvalidAmount,
		InvalidFee,
	}

	#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, TypeInfo, PalletError)]
	pub enum SendError {
		NotApplicable,
		NotRoutable,
		Transport,
		DestinationUnsupported,
		ExceedsMaxMessageSize,
		MissingArgument,
		Fees,
	}

	impl<T: Config> From<XcmpSendError> for Error<T> {
		fn from(e: XcmpSendError) -> Self {
			match e {
				XcmpSendError::NotApplicable => Error::<T>::Send(SendError::NotApplicable),
				XcmpSendError::Unroutable => Error::<T>::Send(SendError::NotRoutable),
				XcmpSendError::Transport(_) => Error::<T>::Send(SendError::Transport),
				XcmpSendError::DestinationUnsupported =>
					Error::<T>::Send(SendError::DestinationUnsupported),
				XcmpSendError::ExceedsMaxMessageSize =>
					Error::<T>::Send(SendError::ExceedsMaxMessageSize),
				XcmpSendError::MissingArgument => Error::<T>::Send(SendError::MissingArgument),
				XcmpSendError::Fees => Error::<T>::Send(SendError::Fees),
			}
		}
	}

	#[pallet::storage]
	pub type RewardsMapping<T: Config> =
		StorageMap<_, Identity, AccountIdOf<T>, BalanceOf<T>, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight((T::WeightInfo::claim(), DispatchClass::Operational))]
		pub fn claim(
			origin: OriginFor<T>,
			deposit_address: AccountIdOf<T>,
			value: BalanceOf<T>,
			message_id: H256,
		) -> DispatchResult {
			let account_id = ensure_signed(origin)?;
			Self::process_claim(account_id, deposit_address, value, message_id)?;
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn process_claim(
			account_id: AccountIdOf<T>,
			deposit_address: AccountIdOf<T>,
			value: BalanceOf<T>,
			message_id: H256,
		) -> DispatchResult {
			// Check if the claim value is equal to or less than the accumulated balance.
			let reward_balance = RewardsMapping::<T>::get(account_id.clone());
			if value > reward_balance {
				return Err(Error::<T>::InsufficientFunds.into());
			}

			let reward_asset = snowbridge_core::location::convert_token_address(
				T::EthereumNetwork::get(),
				T::WethAddress::get(),
			);
			let cost2: u128 =
				TryInto::<u128>::try_into(value).map_err(|_| Error::<T>::InvalidAmount)?;
			let deposit: Asset = (reward_asset, cost2).into();
			let beneficiary: Location =
				Location::new(0, Parachain(T::AssetHubParaId::get().into()));
			let bridge_location = Location::new(2, GlobalConsensus(T::EthereumNetwork::get()));

			let xcm_fee: u128 = 10_000_000_000; // TODO not sure what this should be
			let asset_hub_fee_asset: Asset = (Location::parent(), xcm_fee).into();

			let fee: BalanceOf<T> = xcm_fee.try_into().map_err(|_| Error::<T>::InvalidFee)?;
			Self::burn_fees(T::AssetHubParaId::get().into(), fee)?;

			let xcm: Xcm<()> = alloc::vec![
				// Teleport required fees.
				ReceiveTeleportedAsset(asset_hub_fee_asset.clone().into()),
				// Pay for execution.
				BuyExecution { fees: asset_hub_fee_asset, weight_limit: Unlimited },
				DescendOrigin(PalletInstance(80).into()),
				UniversalOrigin(GlobalConsensus(T::EthereumNetwork::get())),
				ReserveAssetDeposited(deposit.clone().into()),
				DepositAsset { assets: Definite(deposit.into()), beneficiary },
				SetAppendix(Xcm(alloc::vec![
					RefundSurplus,
					DepositAsset { assets: AllCounted(1).into(), beneficiary: bridge_location },
				])),
				SetTopic(message_id.into()),
			]
			.into();

			// Deduct the reward from the claimable balance
			RewardsMapping::<T>::mutate(account_id.clone(), |current_value| {
				*current_value = current_value.saturating_sub(value);
			});

			let dest = Location::new(1, [Parachain(T::AssetHubParaId::get().into())]);
			let (_xcm_hash, _) = send_xcm::<T::XcmSender>(dest, xcm).map_err(Error::<T>::from)?;

			Self::deposit_event(Event::RewardClaimed {
				account_id,
				deposit_address,
				value,
				message_id,
			});
			Ok(())
		}

		/// Burn the amount of the fee embedded into the XCM for teleports
		pub fn burn_fees(para_id: ParaId, fee: BalanceOf<T>) -> DispatchResult {
			let dummy_context =
				XcmContext { origin: None, message_id: Default::default(), topic: None };
			let dest = Location::new(1, [Parachain(para_id.into())]);
			let fees = (Location::parent(), fee.saturated_into::<u128>()).into();
			T::AssetTransactor::can_check_out(&dest, &fees, &dummy_context).map_err(|error| {
				log::error!(
					target: LOG_TARGET,
					"XCM asset check out failed with error {:?}", error
				);
				TokenError::FundsUnavailable
			})?;
			T::AssetTransactor::check_out(&dest, &fees, &dummy_context);
			T::AssetTransactor::withdraw_asset(&fees, &dest, None).map_err(|error| {
				log::error!(
					target: LOG_TARGET,
					"XCM asset withdraw failed with error {:?}", error
				);
				TokenError::FundsUnavailable
			})?;
			Ok(())
		}
	}

	impl<T: Config> RewardLedger<AccountIdOf<T>, BalanceOf<T>> for Pallet<T> {
		fn deposit(account_id: AccountIdOf<T>, value: BalanceOf<T>) -> DispatchResult {
			RewardsMapping::<T>::mutate(account_id.clone(), |current_value| {
				*current_value = current_value.saturating_add(value);
			});
			Self::deposit_event(Event::RewardDeposited { account_id, value });

			Ok(())
		}
	}
}
