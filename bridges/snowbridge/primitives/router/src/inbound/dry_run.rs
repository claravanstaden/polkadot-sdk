// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
extern crate alloc;

use crate::inbound::v2::{ConvertMessage, Message};
use codec::{Decode, Encode};
use frame_support::{
	dispatch::{GetDispatchInfo, PostDispatchInfo},
	Parameter,
};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{Dispatchable, PhantomData},
	Weight,
};
use xcm::{
	latest::Xcm,
	opaque::latest::{ExecuteXcm, Junction::Parachain, Location},
};
use xcm_builder::InspectMessageQueues;

#[derive(Copy, Clone, Encode, Decode, Eq, PartialEq, Debug, TypeInfo)]
pub enum DryRunError {
	/// Message cannot be decoded.
	InvalidPayload,
	/// An API call is unsupported.
	Unimplemented,
	/// Converting a versioned data structure from one version to another failed.
	VersionedConversionFailed,
}

pub trait DryRunMessage {
	fn dry_run_xcm(message: Message) -> Result<Xcm<()>, DryRunError>;
}

pub struct MessageToFeeEstimate<Runtime, Router, RuntimeCall, XcmExecutor, MessageConverter>
where
	Runtime: frame_system::Config,
	Router: InspectMessageQueues,
	RuntimeCall: Parameter
		+ GetDispatchInfo
		+ Dispatchable<RuntimeOrigin = <Runtime>::RuntimeOrigin, PostInfo = PostDispatchInfo>,
	XcmExecutor: ExecuteXcm<<Runtime>::RuntimeCall>,
	MessageConverter: ConvertMessage,
{
	_phantom: PhantomData<(Runtime, Router, RuntimeCall, XcmExecutor, MessageConverter)>,
}

impl<Runtime, Router, RuntimeCall, XcmExecutor, MessageConverter> DryRunMessage
	for MessageToFeeEstimate<Runtime, Router, RuntimeCall, XcmExecutor, MessageConverter>
where
	Runtime: frame_system::Config<RuntimeCall = RuntimeCall>,
	Router: InspectMessageQueues,
	RuntimeCall: Parameter
		+ GetDispatchInfo
		+ Dispatchable<RuntimeOrigin = <Runtime>::RuntimeOrigin, PostInfo = PostDispatchInfo>,
	XcmExecutor: ExecuteXcm<<Runtime>::RuntimeCall>,
	MessageConverter: ConvertMessage,
{
	fn dry_run_xcm(message: Message) -> Result<Xcm<()>, DryRunError> {
		let message_xcm =
			MessageConverter::convert(message).map_err(|_| DryRunError::InvalidPayload)?;
		let origin_location = Location::new(1, Parachain(1002));

		let xcm_program = Xcm::<RuntimeCall>::from(message_xcm.clone().try_into().unwrap());

		let origin_location: Location = origin_location
			.try_into()
			.map_err(|_| DryRunError::VersionedConversionFailed)?;
		let xcm: Xcm<RuntimeCall> =
			xcm_program.try_into().map_err(|_| DryRunError::VersionedConversionFailed)?;
		let mut hash = xcm.using_encoded(sp_io::hashing::blake2_256);
		frame_system::Pallet::<Runtime>::reset_events(); // To make sure we only record events from current call.
		let _result = XcmExecutor::prepare_and_execute(
			origin_location,
			xcm,
			&mut hash,
			Weight::MAX, // Max limit available for execution.
			Weight::zero(),
		);
		let _forwarded_xcms = Router::get_messages();
		let _events: alloc::vec::Vec<<Runtime as frame_system::Config>::RuntimeEvent> =
			frame_system::Pallet::<Runtime>::read_events_no_consensus()
				.map(|record| record.event.clone())
				.collect();
		Ok(alloc::vec![].into())
	}
}
