// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! AMD certificate chain validation for Azure SEV-SNP evidence.
//!
//! Ported from the `az-snp-vtpm` crate (MIT, Microsoft). That crate cannot be
//! depended on directly: its manifest pulls `az-cvm-vtpm` with default features,
//! which enable `tpm` and therefore `tss-esapi`, and `tss-esapi-sys` builds only
//! where libtss2 is available. Only the pieces this verifier uses are kept.

use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidateError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("ARK is not self-signed")]
    ArkNotSelfSigned,
    #[error("ASK is not signed by ARK")]
    AskNotSignedByArk,
    #[error("VCEK is not signed by ASK (or not valid at verification time)")]
    VcekNotSignedByAsk,
}

pub struct AmdChain {
    pub ask: X509,
    pub ark: X509,
}

impl AmdChain {
    pub fn validate(&self) -> Result<(), ValidateError> {
        let ark_pubkey = self.ark.public_key()?;

        if !self.ark.verify(&ark_pubkey)? {
            return Err(ValidateError::ArkNotSelfSigned);
        }

        if !self.ask.verify(&ark_pubkey)? {
            return Err(ValidateError::AskNotSignedByArk);
        }

        Ok(())
    }
}

pub struct Vcek(pub X509);

impl Vcek {
    #[cfg(test)]
    pub fn from_pem(pem: &str) -> Result<Self, openssl::error::ErrorStack> {
        Ok(Self(X509::from_pem(pem.as_bytes())?))
    }

    pub fn validate(&self, amd_chain: &AmdChain) -> Result<(), ValidateError> {
        let ask_pubkey = amd_chain.ask.public_key()?;
        if !self.0.verify(&ask_pubkey)? {
            return Err(ValidateError::VcekNotSignedByAsk);
        }

        let now = Asn1Time::days_from_now(0)?;
        let valid_range = self.0.not_before()..self.0.not_after();
        if !valid_range.contains(&now) {
            return Err(ValidateError::VcekNotSignedByAsk);
        }

        Ok(())
    }
}
