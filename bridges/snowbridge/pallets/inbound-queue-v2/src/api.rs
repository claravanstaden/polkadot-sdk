// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
//! Implements the dry-run API.

use crate::{Config, Error};
use snowbridge_core::inbound::Proof;
use snowbridge_router_primitives::inbound::{dry_run::DryRunMessage, v2::Message};
use xcm::latest::Xcm;
pub fn dry_run<T>(message: Message, _proof: Proof) -> Result<(Xcm<()>, u128), Error<T>>
where
	T: Config,
{
	let _dry_run_result = T::XCMDryRunner::dry_run_xcm(message);
	Ok((Xcm::<()>::new(), 0))
}
