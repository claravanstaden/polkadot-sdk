// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
//! Inbound Queue
//!
//! # Overview
//!
//! Receives messages emitted by the Gateway contract on Ethereum, whereupon they are verified,
//! translated to XCM, and finally sent to their final destination parachain.
//!
//! The message relayers are rewarded using native currency from the sovereign account of the
//! destination parachain.
//!
//! # Extrinsics
//!
//! ## Governance
//!
//! * [`Call::set_operating_mode`]: Set the operating mode of the pallet. Can be used to disable
//!   processing of inbound messages.
//!
//! ## Message Submission
//!
//! * [`Call::submit`]: Submit a message for verification and dispatch the final destination
//!   parachain.
#![cfg_attr(not(feature = "std"), no_std)]

mod envelope;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod test;

use codec::{Decode, DecodeAll, Encode};
use envelope::Envelope;
use frame_support::PalletError;
use frame_system::ensure_signed;
use scale_info::TypeInfo;
use sp_core::H160;
use sp_std::vec;
use xcm::{
	prelude::{send_xcm, Junction::*, Location, SendError as XcmpSendError, SendXcm, Xcm},
	VersionedXcm, MAX_XCM_DECODE_DEPTH,
};

use snowbridge_core::{
	inbound::{Message, VerificationError, Verifier},
	BasicOperatingMode,
};
use snowbridge_router_primitives_v2::inbound::Message as MessageV2;

pub use weights::WeightInfo;

#[cfg(feature = "runtime-benchmarks")]
use snowbridge_beacon_primitives::BeaconHeader;

pub use pallet::*;

pub const LOG_TARGET: &str = "snowbridge-inbound-queue:v2";

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use codec::DecodeLimit;

	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_core::H256;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[cfg(feature = "runtime-benchmarks")]
	pub trait BenchmarkHelper<T> {
		fn initialize_storage(beacon_header: BeaconHeader, block_roots_root: H256);
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// The verifier for inbound messages from Ethereum
		type Verifier: Verifier;

		/// XCM message sender
		type XcmSender: SendXcm;

		/// Address of the Gateway contract
		#[pallet::constant]
		type GatewayAddress: Get<H160>;

		type WeightInfo: WeightInfo;

		#[cfg(feature = "runtime-benchmarks")]
		type Helper: BenchmarkHelper<Self>;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A message was received from Ethereum
		MessageReceived {
			/// The message nonce
			nonce: u64,
			/// ID of the XCM message which was forwarded to the final destination parachain
			message_id: [u8; 32],
		},
		/// Set OperatingMode
		OperatingModeChanged { mode: BasicOperatingMode },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Message came from an invalid outbound channel on the Ethereum side.
		InvalidGateway,
		/// Message has an invalid envelope.
		InvalidEnvelope,
		/// Message has an unexpected nonce.
		InvalidNonce,
		/// Message has an invalid payload.
		InvalidPayload,
		/// Message channel is invalid
		InvalidChannel,
		/// The max nonce for the type has been reached
		MaxNonceReached,
		/// Cannot convert location
		InvalidAccountConversion,
		/// Pallet is halted
		Halted,
		/// Message verification error,
		Verification(VerificationError),
		/// XCMP send failure
		Send(SendError),
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

	/// The nonce of the message been processed or not
	#[pallet::storage]
	pub type Nonce<T: Config> = StorageMap<_, Identity, u64, bool, ValueQuery>;

	/// The current operating mode of the pallet.
	#[pallet::storage]
	#[pallet::getter(fn operating_mode)]
	pub type OperatingMode<T: Config> = StorageValue<_, BasicOperatingMode, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Submit an inbound message originating from the Gateway contract on Ethereum
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::submit())]
		pub fn submit(origin: OriginFor<T>, message: Message) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			ensure!(!Self::operating_mode().is_halted(), Error::<T>::Halted);

			// submit message to verifier for verification
			T::Verifier::verify(&message.event_log, &message.proof)
				.map_err(|e| Error::<T>::Verification(e))?;

			// Decode event log into an Envelope
			let envelope =
				Envelope::try_from(&message.event_log).map_err(|_| Error::<T>::InvalidEnvelope)?;

			// Verify that the message was submitted from the known Gateway contract
			ensure!(T::GatewayAddress::get() == envelope.gateway, Error::<T>::InvalidGateway);

			// Verify the message has not been processed
			ensure!(!<Nonce<T>>::contains_key(envelope.nonce), Error::<T>::InvalidNonce);

			// Decode payload into `MessageV2`
			let message = MessageV2::decode_all(&mut envelope.payload.as_ref())
				.map_err(|_| Error::<T>::InvalidPayload)?;

			// Decode xcm
			let versioned_xcm = VersionedXcm::<()>::decode_with_depth_limit(
				MAX_XCM_DECODE_DEPTH,
				&mut message.xcm.as_ref(),
			)
			.map_err(|_| Error::<T>::InvalidPayload)?;
			let xcm: Xcm<()> = versioned_xcm.try_into().map_err(|_| <Error<T>>::InvalidPayload)?;

			log::info!(
				target: LOG_TARGET,
				"💫 xcm decoded as {:?}",
				xcm,
			);

			// Set nonce flag to true
			<Nonce<T>>::try_mutate(envelope.nonce, |done| -> DispatchResult {
				*done = true;
				Ok(())
			})?;

			// Todo: Deposit fee(in Ether) to RewardLeger which should cover all of:
			// T::RewardLeger::deposit(who, envelope.fee.into())?;
			// a. The submit extrinsic cost on BH
			// b. The delivery cost to AH
			// c. The execution cost on AH
			// d. The execution cost on destination chain(if any)
			// e. The reward

			// Attempt to forward XCM to AH
			let dest = Location::new(1, [Parachain(1000)]);
			let (message_id, _) = send_xcm::<T::XcmSender>(dest, xcm).map_err(Error::<T>::from)?;

			Self::deposit_event(Event::MessageReceived { nonce: envelope.nonce, message_id });

			Ok(())
		}

		/// Halt or resume all pallet operations. May only be called by root.
		#[pallet::call_index(1)]
		#[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
		pub fn set_operating_mode(
			origin: OriginFor<T>,
			mode: BasicOperatingMode,
		) -> DispatchResult {
			ensure_root(origin)?;
			OperatingMode::<T>::set(mode);
			Self::deposit_event(Event::OperatingModeChanged { mode });
			Ok(())
		}
	}
}
