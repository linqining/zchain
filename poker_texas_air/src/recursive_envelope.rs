//! Versioned transport envelope for one Texas recursive STWO proof.
//!
//! The envelope carries the recursive proof, its STWO public inputs, and the VM task material
//! needed by a verifier to reconstruct the Texas AIR statement.  Carrying a task does not make it
//! trusted: production verification must replay it and bind its roots/digest to verifier-owned L1
//! public I/O before calling the recursive verifier.

use bincode::Options;

use crate::error::{TexasAirError, TexasAirResult};
use crate::prove_task::ProveTask;
use poker_zkvm::stwo_backend::recursive::RecursivePublicInputs;
use poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof;

/// Magic bytes identifying a Texas recursive-proof envelope.
pub const TEXAS_RECURSIVE_ENVELOPE_MAGIC: [u8; 8] = *b"ZTXRSTWO";
/// Current envelope wire version.
pub const TEXAS_RECURSIVE_ENVELOPE_VERSION: u16 = 1;
/// Maximum accepted encoded envelope size.
pub const MAX_TEXAS_RECURSIVE_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum accepted serialized task size.
pub const MAX_TEXAS_RECURSIVE_TASK_BYTES: usize = 1024 * 1024;
/// Maximum accepted serialized recursive public-input size.
pub const MAX_TEXAS_RECURSIVE_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum accepted serialized recursive proof size.
pub const MAX_TEXAS_RECURSIVE_PROOF_BYTES: usize = 512 * 1024;

const HEADER_BYTES: usize = 8 + 2 + 2 + 4 + 4 + 4;

/// Decoded Texas recursive-proof envelope.
#[derive(Debug, Clone)]
pub struct TexasRecursiveProofEnvelope {
    task: ProveTask,
    recursive_inputs: RecursivePublicInputs,
    recursive_proof: RecursiveProof,
}

impl TexasRecursiveProofEnvelope {
    /// Construct an envelope from a task and the recursive prover output.
    #[must_use]
    pub const fn new(
        task: ProveTask,
        recursive_inputs: RecursivePublicInputs,
        recursive_proof: RecursiveProof,
    ) -> Self {
        Self {
            task,
            recursive_inputs,
            recursive_proof,
        }
    }

    /// Task material that the verifier must replay and independently bind.
    #[must_use]
    pub const fn task(&self) -> &ProveTask {
        &self.task
    }

    /// Recursive STWO public inputs.
    #[must_use]
    pub const fn recursive_inputs(&self) -> &RecursivePublicInputs {
        &self.recursive_inputs
    }

    /// Recursive STWO proof; no inner method proof is carried.
    #[must_use]
    pub const fn recursive_proof(&self) -> &RecursiveProof {
        &self.recursive_proof
    }

    /// Encode the envelope using explicit lengths and a fixed versioned header.
    ///
    /// # Errors
    ///
    /// Returns an error when a section cannot be serialized or exceeds its protocol limit.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        let task = borsh::to_vec(&self.task).map_err(|error| {
            TexasAirError::SerializationError(format!("recursive task borsh encode: {error}"))
        })?;
        let recursive_inputs = bounded_bincode(MAX_TEXAS_RECURSIVE_INPUT_BYTES as u64)
            .serialize(&self.recursive_inputs)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "recursive public inputs encode: {error}"
                ))
            })?;
        let recursive_proof = bounded_bincode(MAX_TEXAS_RECURSIVE_PROOF_BYTES as u64)
            .serialize(&self.recursive_proof)
            .map_err(|error| {
                TexasAirError::SerializationError(format!("recursive proof encode: {error}"))
            })?;

        validate_section_lengths(task.len(), recursive_inputs.len(), recursive_proof.len())?;
        let total = HEADER_BYTES
            .checked_add(task.len())
            .and_then(|value| value.checked_add(recursive_inputs.len()))
            .and_then(|value| value.checked_add(recursive_proof.len()))
            .ok_or_else(|| {
                TexasAirError::SerializationError("recursive envelope length overflow".into())
            })?;
        if total > MAX_TEXAS_RECURSIVE_ENVELOPE_BYTES {
            return Err(TexasAirError::SerializationError(format!(
                "recursive envelope size {total} exceeds {}",
                MAX_TEXAS_RECURSIVE_ENVELOPE_BYTES
            )));
        }

        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&TEXAS_RECURSIVE_ENVELOPE_MAGIC);
        encoded.extend_from_slice(&TEXAS_RECURSIVE_ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&0u16.to_be_bytes());
        encoded.extend_from_slice(&usize_to_u32(task.len())?.to_be_bytes());
        encoded.extend_from_slice(&usize_to_u32(recursive_inputs.len())?.to_be_bytes());
        encoded.extend_from_slice(&usize_to_u32(recursive_proof.len())?.to_be_bytes());
        encoded.extend_from_slice(&task);
        encoded.extend_from_slice(&recursive_inputs);
        encoded.extend_from_slice(&recursive_proof);
        Ok(encoded)
    }

    /// Decode and structurally validate an envelope without verifying its proof.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions/flags, oversized sections, truncated data, trailing bytes, and
    /// malformed task/public-input/proof payloads.
    pub fn decode(encoded: &[u8]) -> TexasAirResult<Self> {
        if encoded.len() < HEADER_BYTES || encoded.len() > MAX_TEXAS_RECURSIVE_ENVELOPE_BYTES {
            return Err(TexasAirError::SerializationError(format!(
                "recursive envelope size {} is outside [{HEADER_BYTES}, {}]",
                encoded.len(),
                MAX_TEXAS_RECURSIVE_ENVELOPE_BYTES
            )));
        }
        if encoded[..8] != TEXAS_RECURSIVE_ENVELOPE_MAGIC {
            return Err(TexasAirError::SerializationError(
                "recursive envelope magic mismatch".into(),
            ));
        }
        let version = u16::from_be_bytes([encoded[8], encoded[9]]);
        if version != TEXAS_RECURSIVE_ENVELOPE_VERSION {
            return Err(TexasAirError::SerializationError(format!(
                "unsupported recursive envelope version {version}"
            )));
        }
        let flags = u16::from_be_bytes([encoded[10], encoded[11]]);
        if flags != 0 {
            return Err(TexasAirError::SerializationError(format!(
                "unsupported recursive envelope flags 0x{flags:04x}"
            )));
        }

        let task_len = read_u32(encoded, 12)? as usize;
        let inputs_len = read_u32(encoded, 16)? as usize;
        let proof_len = read_u32(encoded, 20)? as usize;
        validate_section_lengths(task_len, inputs_len, proof_len)?;
        let expected = HEADER_BYTES
            .checked_add(task_len)
            .and_then(|value| value.checked_add(inputs_len))
            .and_then(|value| value.checked_add(proof_len))
            .ok_or_else(|| {
                TexasAirError::SerializationError("recursive envelope length overflow".into())
            })?;
        if expected != encoded.len() {
            return Err(TexasAirError::SerializationError(format!(
                "recursive envelope length mismatch: header={expected}, actual={}",
                encoded.len()
            )));
        }

        let task_end = HEADER_BYTES + task_len;
        let inputs_end = task_end + inputs_len;
        let task = borsh::from_slice(&encoded[HEADER_BYTES..task_end]).map_err(|error| {
            TexasAirError::SerializationError(format!("recursive task borsh decode: {error}"))
        })?;
        let recursive_inputs = bounded_bincode(MAX_TEXAS_RECURSIVE_INPUT_BYTES as u64)
            .deserialize(&encoded[task_end..inputs_end])
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "recursive public inputs decode: {error}"
                ))
            })?;
        let recursive_proof = bounded_bincode(MAX_TEXAS_RECURSIVE_PROOF_BYTES as u64)
            .deserialize(&encoded[inputs_end..])
            .map_err(|error| {
                TexasAirError::SerializationError(format!("recursive proof decode: {error}"))
            })?;
        Ok(Self::new(task, recursive_inputs, recursive_proof))
    }
}

fn bounded_bincode(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}

fn validate_section_lengths(task: usize, inputs: usize, proof: usize) -> TexasAirResult<()> {
    for (name, actual, limit) in [
        ("task", task, MAX_TEXAS_RECURSIVE_TASK_BYTES),
        ("public inputs", inputs, MAX_TEXAS_RECURSIVE_INPUT_BYTES),
        ("proof", proof, MAX_TEXAS_RECURSIVE_PROOF_BYTES),
    ] {
        if actual == 0 || actual > limit {
            return Err(TexasAirError::SerializationError(format!(
                "recursive {name} section size {actual} is outside [1, {limit}]"
            )));
        }
    }
    Ok(())
}

fn usize_to_u32(value: usize) -> TexasAirResult<u32> {
    u32::try_from(value).map_err(|_| {
        TexasAirError::SerializationError("recursive envelope section does not fit u32".into())
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> TexasAirResult<u32> {
    let raw = bytes.get(offset..offset + 4).ok_or_else(|| {
        TexasAirError::SerializationError("truncated recursive envelope header".into())
    })?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_unknown_version_before_payload_parsing() {
        let mut encoded = vec![0u8; HEADER_BYTES];
        encoded[..8].copy_from_slice(&TEXAS_RECURSIVE_ENVELOPE_MAGIC);
        encoded[8..10].copy_from_slice(&(TEXAS_RECURSIVE_ENVELOPE_VERSION + 1).to_be_bytes());
        assert!(TexasRecursiveProofEnvelope::decode(&encoded).is_err());
    }

    #[test]
    fn decode_rejects_declared_length_mismatch() {
        let mut encoded = vec![0u8; HEADER_BYTES];
        encoded[..8].copy_from_slice(&TEXAS_RECURSIVE_ENVELOPE_MAGIC);
        encoded[8..10].copy_from_slice(&TEXAS_RECURSIVE_ENVELOPE_VERSION.to_be_bytes());
        encoded[12..16].copy_from_slice(&1u32.to_be_bytes());
        encoded[16..20].copy_from_slice(&1u32.to_be_bytes());
        encoded[20..24].copy_from_slice(&1u32.to_be_bytes());
        assert!(TexasRecursiveProofEnvelope::decode(&encoded).is_err());
    }
}
