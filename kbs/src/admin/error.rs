// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin access denied: {reason}")]
    AdminAccessDenied { reason: String },

    #[error("Failed to parse admin public key")]
    ParsePublicKey(#[from] jwt_simple::Error),

    #[error("Failed to parse HTTP Auth Bearer header")]
    ParseAuthHeaderFailed(#[from] actix_web::error::ParseError),

    #[error("Read admin public key failed")]
    ReadPublicKey(#[from] std::io::Error),

    #[error("Invalid Regular Expression in Role")]
    InvalidRoleRegex(#[from] regex::Error),

    #[error("Duplicate Admin Role")]
    DuplicateAdminRole,
}
