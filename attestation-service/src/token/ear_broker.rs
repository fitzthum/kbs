// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

//use ear::{Algorithm, Appraisal, Ear, Extensions, VerifierID};
use ear::{Algorithm, Appraisal, Ear, RawValue, VerifierID};
use kbs_types::Tee;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use regorus::Value;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use crate::AttestationTokenBroker;
use crate::token::AttestationTokenConfig;

pub struct EarAttestationTokenBroker {
    config: AttestationTokenConfig,
    private_key_bytes: Vec<u8>,
    claim_names: Vec<String>,
}

impl EarAttestationTokenBroker {
    pub fn new(config: AttestationTokenConfig) -> Result<Self> {
        let private_key_bytes = match config.clone().signer {
            Some(signer) => std::fs::read(signer.key_path)?,
            None => generate_ec_keys()?.0,
        };

        let claim_names = vec![
            "instance_identity".to_string(),
            "configuration".to_string(),
            "executables".to_string(),
            "file_system".to_string(),
            "hardware".to_string(),
            "runtime_opaque".to_string(),
            "storage_opaque".to_string(),
            "sourced_data".to_string(),
        ];

        Ok(Self {
            config,
            private_key_bytes,
            claim_names,
        })
    }
}

impl AttestationTokenBroker for EarAttestationTokenBroker {
    fn rules(&self) -> Vec<String> {
        self.claim_names.clone()
    }

    fn issue(
        &self,
        policy_results: HashMap<String, regorus::Value>,
        tcb_claims: BTreeMap<String, RawValue>,
        policy_id: String,
        init_data_claims: serde_json::Value,
        runtime_data_claims: serde_json::Value,
        tee: Tee,
    ) -> Result<String> {

        let mut appraisal = Appraisal::new();

        for rule in self.claim_names.clone() {
            if policy_results.contains_key(&rule) {
                let claim_value = policy_results
                    .get(&rule)
                    .unwrap()
                    .as_i8()
                    .context("Policy claim value not i8")?;

                appraisal
                    .trust_vector
                    .mut_by_name(&rule)
                    .unwrap()
                    .set(claim_value);
            }
        }

        if !appraisal.trust_vector.any_set() {
            bail!("At least one policy claim must be set.");
        }

        appraisal.update_status_from_trust_vector();
        appraisal.annotated_evidence = tcb_claims;
        appraisal.policy_id = Some(policy_id);

        // For now, create only one submod, called `cpu`.
        // We can create more when we support attesting multiple devices at once.
        let mut submods = BTreeMap::new();
        submods.insert("cpu".to_string(), appraisal);

        let now = time::OffsetDateTime::now_utc();

        let ear = Ear {
            profile: self.config.profile_name.clone(),
            iat: now.unix_timestamp(),
            vid: VerifierID {
                build: self.config.build_name.clone(),
                developer: self.config.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            //extensions: Extensions::new(),
        };

        let signed_ear = ear.sign_jwt_pem(Algorithm::ES256, &self.private_key_bytes)?;

        Ok(signed_ear)
    }
}

fn generate_ec_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    Ok((pkey.private_key_to_pem_pkcs8()?, pkey.public_key_to_pem()?))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::DecodingKey;
    use std::collections::BTreeMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_issue_ear_ephemeral_key() {
        let mut submods = BTreeMap::new();
        submods.insert("cpu".to_string(), ear::Appraisal::new());

        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = AttestationTokenConfig::default();
        let broker = AttestationTokenBroker::new(config).unwrap();

        let _token = broker.issue_ear(submods).unwrap();
    }

    #[test]
    fn test_issue_and_validate_ear() {
        let mut submods = BTreeMap::new();
        submods.insert("cpu".to_string(), ear::Appraisal::new());

        let (private_key_bytes, public_key_bytes) = generate_ec_keys().unwrap();

        let mut private_key_file = NamedTempFile::new().unwrap();
        private_key_file.write_all(&private_key_bytes).unwrap();

        let signer = TokenSignerConfig {
            key_path: private_key_file.path().to_str().unwrap().to_string(),
            cert_url: None,
            cert_path: None,
        };

        let mut config = AttestationTokenConfig::default();
        config.signer = Some(signer);

        let broker = AttestationTokenBroker::new(config).unwrap();
        let token = broker.issue_ear(submods).unwrap();

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }
}
