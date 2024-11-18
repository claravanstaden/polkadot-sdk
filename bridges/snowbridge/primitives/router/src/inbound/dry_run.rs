// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
extern crate alloc;

use crate::inbound::v2::{ConvertMessage, Message};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::PhantomData,
};
use xcm::{
	latest::Xcm,
};

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

pub struct MessageToXCM<MessageConverter>
where

	MessageConverter: ConvertMessage,
{
	_phantom: PhantomData<MessageConverter>,
}

impl<MessageConverter> DryRunMessage
	for MessageToXCM<MessageConverter>
where
	MessageConverter: ConvertMessage,
{
	fn dry_run_xcm(message: Message) -> Result<Xcm<()>, DryRunError> {
		let message_xcm =
			MessageConverter::convert(message).map_err(|_| DryRunError::InvalidPayload)?;

		Ok(message_xcm)
	}
}
