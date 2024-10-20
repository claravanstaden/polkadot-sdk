// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
//! Converts XCM messages into simpler commands that can be processed by the Gateway contract

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use core::slice::Iter;
use sp_std::ops::ControlFlow;

use frame_support::{
	ensure,
	traits::{Get, ProcessMessageError},
	BoundedVec,
};
use snowbridge_core::{
	outbound_v2::{Command, Message, SendMessage},
	AgentId, TokenId, TokenIdOf,
};
use sp_core::{H160, H256};
use sp_runtime::traits::MaybeEquivalence;
use sp_std::{iter::Peekable, marker::PhantomData, prelude::*};
use xcm::prelude::*;
use xcm_builder::{CreateMatcher, MatchXcm};
use xcm_executor::traits::{ConvertLocation, ExportXcm};

const TARGET: &'static str = "xcm::ethereum_blob_exporter::v2";

pub struct EthereumBlobExporter<
	UniversalLocation,
	EthereumNetwork,
	OutboundQueue,
	AgentHashedDescription,
	ConvertAssetId,
>(
	PhantomData<(
		UniversalLocation,
		EthereumNetwork,
		OutboundQueue,
		AgentHashedDescription,
		ConvertAssetId,
	)>,
);

impl<UniversalLocation, EthereumNetwork, OutboundQueue, AgentHashedDescription, ConvertAssetId>
	ExportXcm
	for EthereumBlobExporter<
		UniversalLocation,
		EthereumNetwork,
		OutboundQueue,
		AgentHashedDescription,
		ConvertAssetId,
	>
where
	UniversalLocation: Get<InteriorLocation>,
	EthereumNetwork: Get<NetworkId>,
	OutboundQueue: SendMessage<Balance = u128>,
	AgentHashedDescription: ConvertLocation<H256>,
	ConvertAssetId: MaybeEquivalence<TokenId, Location>,
{
	type Ticket = (Vec<u8>, XcmHash);

	fn validate(
		network: NetworkId,
		_channel: u32,
		universal_source: &mut Option<InteriorLocation>,
		destination: &mut Option<InteriorLocation>,
		message: &mut Option<Xcm<()>>,
	) -> SendResult<Self::Ticket> {
		let expected_network = EthereumNetwork::get();
		let universal_location = UniversalLocation::get();

		if network != expected_network {
			log::trace!(target: TARGET, "skipped due to unmatched bridge network {network:?}.");
			return Err(SendError::NotApplicable)
		}

		// Cloning destination to avoid modifying the value so subsequent exporters can use it.
		let dest = destination.clone().take().ok_or(SendError::MissingArgument)?;
		if dest != Here {
			log::trace!(target: TARGET, "skipped due to unmatched remote destination {dest:?}.");
			return Err(SendError::NotApplicable)
		}

		// Cloning universal_source to avoid modifying the value so subsequent exporters can use it.
		let (local_net, local_sub) = universal_source.clone()
			.take()
			.ok_or_else(|| {
				log::error!(target: TARGET, "universal source not provided.");
				SendError::MissingArgument
			})?
			.split_global()
			.map_err(|()| {
				log::error!(target: TARGET, "could not get global consensus from universal source '{universal_source:?}'.");
				SendError::NotApplicable
			})?;

		if Ok(local_net) != universal_location.global_consensus() {
			log::trace!(target: TARGET, "skipped due to unmatched relay network {local_net:?}.");
			return Err(SendError::NotApplicable)
		}

		let _para_id = match local_sub.as_slice() {
			[Parachain(para_id)] => *para_id,
			_ => {
				log::error!(target: TARGET, "could not get parachain id from universal source '{local_sub:?}'.");
				return Err(SendError::NotApplicable)
			},
		};

		let source_location = Location::new(1, local_sub.clone());

		let agent_id = match AgentHashedDescription::convert_location(&source_location) {
			Some(id) => id,
			None => {
				log::error!(target: TARGET, "unroutable due to not being able to create agent id. '{source_location:?}'");
				return Err(SendError::NotApplicable)
			},
		};

		let message = message.clone().ok_or_else(|| {
			log::error!(target: TARGET, "xcm message not provided.");
			SendError::MissingArgument
		})?;

		// An workaround to inspect ExpectAsset as V2 message
		let mut instructions = message.clone().0;
		let result = instructions.matcher().match_next_inst_while(
			|_| true,
			|inst| {
				return match inst {
					ExpectAsset(..) => Err(ProcessMessageError::Unsupported),
					_ => Ok(ControlFlow::Continue(())),
				}
			},
		);
		ensure!(result.is_err(), SendError::NotApplicable);

		let mut converter =
			XcmConverter::<ConvertAssetId, ()>::new(&message, expected_network, agent_id);
		let message = converter.convert().map_err(|err| {
			log::error!(target: TARGET, "unroutable due to pattern matching error '{err:?}'.");
			SendError::Unroutable
		})?;

		// validate the message
		let (ticket, fee) = OutboundQueue::validate(&message).map_err(|err| {
			log::error!(target: TARGET, "OutboundQueue validation of message failed. {err:?}");
			SendError::Unroutable
		})?;

		// convert fee to Asset
		let fee = Asset::from((Location::parent(), fee.total())).into();

		Ok(((ticket.encode(), XcmHash::from(message.id)), fee))
	}

	fn deliver(blob: (Vec<u8>, XcmHash)) -> Result<XcmHash, SendError> {
		let ticket: OutboundQueue::Ticket = OutboundQueue::Ticket::decode(&mut blob.0.as_ref())
			.map_err(|_| {
				log::trace!(target: TARGET, "undeliverable due to decoding error");
				SendError::NotApplicable
			})?;

		let message_id = OutboundQueue::deliver(ticket).map_err(|_| {
			log::error!(target: TARGET, "OutboundQueue submit of message failed");
			SendError::Transport("other transport error")
		})?;

		log::info!(target: TARGET, "message delivered {message_id:#?}.");
		Ok(message_id.into())
	}
}

/// Errors that can be thrown to the pattern matching step.
#[derive(PartialEq, Debug)]
enum XcmConverterError {
	UnexpectedEndOfXcm,
	EndOfXcmMessageExpected,
	WithdrawAssetExpected,
	DepositAssetExpected,
	NoReserveAssets,
	FilterDoesNotConsumeAllAssets,
	TooManyAssets,
	ZeroAssetTransfer,
	BeneficiaryResolutionFailed,
	AssetResolutionFailed,
	InvalidFeeAsset,
	SetTopicExpected,
	ReserveAssetDepositedExpected,
	InvalidAsset,
	UnexpectedInstruction,
	TooManyCommands,
}

macro_rules! match_expression {
	($expression:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $value:expr $(,)?) => {
		match $expression {
			$( $pattern )|+ $( if $guard )? => Some($value),
			_ => None,
		}
	};
}

struct XcmConverter<'a, ConvertAssetId, Call> {
	iter: Peekable<Iter<'a, Instruction<Call>>>,
	ethereum_network: NetworkId,
	agent_id: AgentId,
	_marker: PhantomData<ConvertAssetId>,
}
impl<'a, ConvertAssetId, Call> XcmConverter<'a, ConvertAssetId, Call>
where
	ConvertAssetId: MaybeEquivalence<TokenId, Location>,
{
	fn new(message: &'a Xcm<Call>, ethereum_network: NetworkId, agent_id: AgentId) -> Self {
		Self {
			iter: message.inner().iter().peekable(),
			ethereum_network,
			agent_id,
			_marker: Default::default(),
		}
	}

	fn convert(&mut self) -> Result<Message, XcmConverterError> {
		let result = match self.peek() {
			Ok(ReserveAssetDeposited { .. }) => self.send_native_tokens_message(),
			// Get withdraw/deposit and make native tokens create message.
			Ok(WithdrawAsset { .. }) => self.send_tokens_message(),
			Err(e) => Err(e),
			_ => return Err(XcmConverterError::UnexpectedInstruction),
		}?;

		// All xcm instructions must be consumed before exit.
		if self.next().is_ok() {
			return Err(XcmConverterError::EndOfXcmMessageExpected)
		}

		Ok(result)
	}

	fn send_tokens_message(&mut self) -> Result<Message, XcmConverterError> {
		use XcmConverterError::*;

		// Get the reserve assets from WithdrawAsset.
		let reserve_assets =
			match_expression!(self.next()?, WithdrawAsset(reserve_assets), reserve_assets)
				.ok_or(WithdrawAssetExpected)?;

		// Check if clear origin exists and skip over it.
		if match_expression!(self.peek(), Ok(ClearOrigin), ()).is_some() {
			let _ = self.next();
		}

		// Extract the fee asset item from BuyExecution|PayFees(V5)
		let fee_asset = match_expression!(self.next()?, BuyExecution { fees, .. }, fees)
			.ok_or(InvalidFeeAsset)?;
		// Todo: Validate fee asset is WETH
		let fee_amount = match fee_asset {
			Asset { id: _, fun: Fungible(amount) } => Some(*amount),
			_ => None,
		}
		.ok_or(AssetResolutionFailed)?;

		// Check if ExpectAsset exists and skip over it.
		if match_expression!(self.peek(), Ok(ExpectAsset { .. }), ()).is_some() {
			let _ = self.next();
		}

		let (deposit_assets, beneficiary) = match_expression!(
			self.next()?,
			DepositAsset { assets, beneficiary },
			(assets, beneficiary)
		)
		.ok_or(DepositAssetExpected)?;

		// assert that the beneficiary is AccountKey20.
		let recipient = match_expression!(
			beneficiary.unpack(),
			(0, [AccountKey20 { network, key }])
				if self.network_matches(network),
			H160(*key)
		)
		.ok_or(BeneficiaryResolutionFailed)?;

		// Make sure there are reserved assets.
		if reserve_assets.len() == 0 {
			return Err(NoReserveAssets)
		}

		// Check the the deposit asset filter matches what was reserved.
		if reserve_assets.inner().iter().any(|asset| !deposit_assets.matches(asset)) {
			return Err(FilterDoesNotConsumeAllAssets)
		}

		// We only support a single asset at a time.
		ensure!(reserve_assets.len() == 1, TooManyAssets);
		let reserve_asset = reserve_assets.get(0).ok_or(AssetResolutionFailed)?;

		let (token, amount) = match reserve_asset {
			Asset { id: AssetId(inner_location), fun: Fungible(amount) } =>
				match inner_location.unpack() {
					(0, [AccountKey20 { network, key }]) if self.network_matches(network) =>
						Some((H160(*key), *amount)),
					_ => None,
				},
			_ => None,
		}
		.ok_or(AssetResolutionFailed)?;

		// transfer amount must be greater than 0.
		ensure!(amount > 0, ZeroAssetTransfer);

		// Check if there is a SetTopic and skip over it if found.
		let topic_id = match_expression!(self.next()?, SetTopic(id), id).ok_or(SetTopicExpected)?;

		let message = Message {
			id: (*topic_id).into(),
			// Todo: from XCMV5 AliasOrigin
			origin: H256::zero(),
			fee: fee_amount,
			commands: BoundedVec::try_from(vec![Command::UnlockNativeToken {
				agent_id: self.agent_id,
				token,
				recipient,
				amount,
			}])
			.map_err(|_| TooManyCommands)?,
		};

		Ok(message)
	}

	fn next(&mut self) -> Result<&'a Instruction<Call>, XcmConverterError> {
		self.iter.next().ok_or(XcmConverterError::UnexpectedEndOfXcm)
	}

	fn peek(&mut self) -> Result<&&'a Instruction<Call>, XcmConverterError> {
		self.iter.peek().ok_or(XcmConverterError::UnexpectedEndOfXcm)
	}

	fn network_matches(&self, network: &Option<NetworkId>) -> bool {
		if let Some(network) = network {
			*network == self.ethereum_network
		} else {
			true
		}
	}

	/// Convert the xcm for Polkadot-native token from AH into the Command
	/// To match transfers of Polkadot-native tokens, we expect an input of the form:
	/// # ReserveAssetDeposited
	/// # ClearOrigin
	/// # BuyExecution
	/// # DepositAsset
	/// # SetTopic
	fn send_native_tokens_message(&mut self) -> Result<Message, XcmConverterError> {
		use XcmConverterError::*;

		// Get the reserve assets.
		let reserve_assets =
			match_expression!(self.next()?, ReserveAssetDeposited(reserve_assets), reserve_assets)
				.ok_or(ReserveAssetDepositedExpected)?;

		// Check if clear origin exists and skip over it.
		if match_expression!(self.peek(), Ok(ClearOrigin), ()).is_some() {
			let _ = self.next();
		}

		// Extract the fee asset item from BuyExecution|PayFees(V5)
		let fee_asset = match_expression!(self.next()?, BuyExecution { fees, .. }, fees)
			.ok_or(InvalidFeeAsset)?;
		// Todo: Validate fee asset is WETH
		let fee_amount = match fee_asset {
			Asset { id: _, fun: Fungible(amount) } => Some(*amount),
			_ => None,
		}
		.ok_or(AssetResolutionFailed)?;

		let (deposit_assets, beneficiary) = match_expression!(
			self.next()?,
			DepositAsset { assets, beneficiary },
			(assets, beneficiary)
		)
		.ok_or(DepositAssetExpected)?;

		// assert that the beneficiary is AccountKey20.
		let recipient = match_expression!(
			beneficiary.unpack(),
			(0, [AccountKey20 { network, key }])
				if self.network_matches(network),
			H160(*key)
		)
		.ok_or(BeneficiaryResolutionFailed)?;

		// Make sure there are reserved assets.
		if reserve_assets.len() == 0 {
			return Err(NoReserveAssets)
		}

		// Check the the deposit asset filter matches what was reserved.
		if reserve_assets.inner().iter().any(|asset| !deposit_assets.matches(asset)) {
			return Err(FilterDoesNotConsumeAllAssets)
		}

		// We only support a single asset at a time.
		ensure!(reserve_assets.len() == 1, TooManyAssets);
		let reserve_asset = reserve_assets.get(0).ok_or(AssetResolutionFailed)?;

		let (asset_id, amount) = match reserve_asset {
			Asset { id: AssetId(inner_location), fun: Fungible(amount) } =>
				Some((inner_location.clone(), *amount)),
			_ => None,
		}
		.ok_or(AssetResolutionFailed)?;

		// transfer amount must be greater than 0.
		ensure!(amount > 0, ZeroAssetTransfer);

		let token_id = TokenIdOf::convert_location(&asset_id).ok_or(InvalidAsset)?;

		let expected_asset_id = ConvertAssetId::convert(&token_id).ok_or(InvalidAsset)?;

		ensure!(asset_id == expected_asset_id, InvalidAsset);

		// Check if there is a SetTopic and skip over it if found.
		let topic_id = match_expression!(self.next()?, SetTopic(id), id).ok_or(SetTopicExpected)?;

		let message = Message {
			origin: H256::zero(),
			fee: fee_amount,
			id: (*topic_id).into(),
			commands: BoundedVec::try_from(vec![Command::MintForeignToken {
				token_id,
				recipient,
				amount,
			}])
			.map_err(|_| TooManyCommands)?,
		};

		Ok(message)
	}
}
