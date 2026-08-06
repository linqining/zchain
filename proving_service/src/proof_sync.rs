//! Verified P2P repair/download path for durable Texas proof packages.
//!
//! The wire protocol treats packages as opaque bounded bytes. This module is
//! the business boundary that canonical-decodes the downloaded package, binds
//! it to an existing durable job, replays the method statement and runs native
//! Stwo verification before the sidecar is persisted.

use poker_l1::Hash;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use borsh::BorshDeserialize;
use poker_l1::network::{
    MAX_P2P_MESSAGE_BYTES, NetworkMessage, NetworkTransport, ProofPackageAssembler,
    ProofPackageChunk, ProofPackageManifest,
};
use poker_texas_air::orchestrator::Orchestrator;

use crate::proof_package::{ServiceProofPackage, stored_proof_metadata};
use crate::repository::{ServiceRepository, StoredJobStatus};
use crate::{ServiceError, ServiceResult};

/// Result of one fully verified package synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofPackageSyncReport {
    pub job_id: Hash,
    pub package_hash: Hash,
    pub total_len: u64,
    pub chunk_count: u32,
    pub method: &'static str,
    pub table_id: u64,
    pub hand_id: u32,
    pub call_seq: u32,
}

/// Narrow peer interface required by proof-package synchronization.
pub trait ProofPackagePeer {
    fn request_manifest(&self, job_id: Hash) -> ServiceResult<Option<ProofPackageManifest>>;

    fn request_chunk(
        &self,
        manifest: &ProofPackageManifest,
        index: u32,
    ) -> ServiceResult<Option<ProofPackageChunk>>;
}

impl<T: NetworkTransport + ?Sized> ProofPackagePeer for T {
    fn request_manifest(&self, job_id: Hash) -> ServiceResult<Option<ProofPackageManifest>> {
        self.request_proof_package_manifest(job_id)
            .map_err(network_error)
    }

    fn request_chunk(
        &self,
        manifest: &ProofPackageManifest,
        index: u32,
    ) -> ServiceResult<Option<ProofPackageChunk>> {
        let chunk = self
            .request_proof_package_chunk(manifest.job_id, manifest.package_hash, index)
            .map_err(network_error)?;
        if let Some(chunk) = &chunk {
            chunk.validate_against(manifest).map_err(network_error)?;
        }
        Ok(chunk)
    }
}

/// Minimal TCP client for syncing from one or more zchain P2P listeners.
#[derive(Debug, Clone)]
pub struct TcpProofPackagePeer {
    peers: Vec<SocketAddr>,
    timeout: Duration,
    max_attempts: usize,
}

const DEFAULT_PEER_ATTEMPTS: usize = 3;

impl TcpProofPackagePeer {
    /// Construct a client with deterministic peer order and the default 30s timeout.
    pub fn new(peers: Vec<SocketAddr>) -> ServiceResult<Self> {
        if peers.is_empty() {
            return Err(ServiceError::Runner(
                "proof package sync requires at least one peer".into(),
            ));
        }
        Ok(Self {
            peers,
            timeout: Duration::from_secs(30),
            max_attempts: DEFAULT_PEER_ATTEMPTS,
        })
    }

    /// Construct a client with explicit timeout and bounded retry attempts.
    ///
    /// An attempt opens a fresh TCP connection, so transient connection and
    /// framed-read failures do not permanently exclude an otherwise healthy
    /// peer. A value of zero is rejected to avoid silently disabling repair.
    pub fn with_timeout_and_attempts(
        peers: Vec<SocketAddr>,
        timeout: Duration,
        max_attempts: usize,
    ) -> ServiceResult<Self> {
        if peers.is_empty() {
            return Err(ServiceError::Runner(
                "proof package sync requires at least one peer".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(ServiceError::Runner(
                "proof package sync timeout must be non-zero".into(),
            ));
        }
        if max_attempts == 0 {
            return Err(ServiceError::Runner(
                "proof package sync retry attempts must be non-zero".into(),
            ));
        }
        Ok(Self {
            peers,
            timeout,
            max_attempts,
        })
    }

    fn request_from_first_available<T, F>(
        &self,
        operation: &str,
        mut request: F,
    ) -> ServiceResult<Option<T>>
    where
        F: FnMut(SocketAddr) -> ServiceResult<Option<T>>,
    {
        let mut failures = Vec::new();
        let mut missing = 0usize;
        for peer in &self.peers {
            for attempt in 1..=self.max_attempts {
                match request(*peer) {
                    Ok(Some(response)) => return Ok(Some(response)),
                    Ok(None) => {
                        // A well-formed negative response is authoritative for
                        // this peer; retrying it only adds load.
                        missing += 1;
                        break;
                    }
                    Err(error) => failures.push(format!(
                        "{peer} attempt {attempt}/{}: {error}",
                        self.max_attempts
                    )),
                }
            }
        }
        if failures.is_empty() {
            return Ok(None);
        }
        Err(ServiceError::Runner(format!(
            "no proof package peer supplied a valid {operation} response ({missing} missing): {}",
            failures.join("; ")
        )))
    }
}

impl ProofPackagePeer for TcpProofPackagePeer {
    fn request_manifest(&self, job_id: Hash) -> ServiceResult<Option<ProofPackageManifest>> {
        self.request_from_first_available("manifest", |peer| {
            let response = request_one_peer(
                peer,
                self.timeout,
                &NetworkMessage::RequestProofPackageManifest(job_id),
                &mut |message| matches!(message, NetworkMessage::ResponseProofPackageManifest(_)),
            )?;
            let NetworkMessage::ResponseProofPackageManifest(manifest) = response else {
                unreachable!("response selector accepted only manifest responses");
            };
            let Some(manifest) = manifest else {
                return Ok(None);
            };
            manifest.validate().map_err(network_error)?;
            if manifest.job_id != job_id {
                return Err(ServiceError::Runner(
                    "proof package manifest does not target requested job".into(),
                ));
            }
            Ok(Some(manifest))
        })
    }

    fn request_chunk(
        &self,
        manifest: &ProofPackageManifest,
        index: u32,
    ) -> ServiceResult<Option<ProofPackageChunk>> {
        self.request_from_first_available("chunk", |peer| {
            let response = request_one_peer(
                peer,
                self.timeout,
                &NetworkMessage::RequestProofPackageChunk {
                    job_id: manifest.job_id,
                    package_hash: manifest.package_hash,
                    index,
                },
                &mut |message| matches!(message, NetworkMessage::ResponseProofPackageChunk(_)),
            )?;
            let NetworkMessage::ResponseProofPackageChunk(chunk) = response else {
                unreachable!("response selector accepted only chunk responses");
            };
            let Some(chunk) = chunk else {
                return Ok(None);
            };
            chunk.validate_against(manifest).map_err(network_error)?;
            Ok(Some(chunk))
        })
    }
}

/// Download and durably repair one completed job's proof sidecar.
///
/// An untrusted peer can choose bytes and manifest metadata, but cannot make
/// them durable unless the complete hash, canonical package schema, local job
/// metadata, canonical VM replay and native method-proof verification all pass.
pub fn sync_proof_package(
    repository: &mut ServiceRepository,
    peer: &dyn ProofPackagePeer,
    job_id: Hash,
) -> ServiceResult<ProofPackageSyncReport> {
    let manifest = peer
        .request_manifest(job_id)?
        .ok_or_else(|| ServiceError::Runner("proof package manifest not found".into()))?;
    manifest.validate().map_err(network_error)?;
    if manifest.job_id != job_id {
        return Err(ServiceError::Runner(
            "proof package manifest does not target requested job".into(),
        ));
    }

    let mut assembler = ProofPackageAssembler::new(manifest.clone()).map_err(network_error)?;
    for index in 0..manifest.chunk_count {
        let chunk = peer.request_chunk(&manifest, index)?.ok_or_else(|| {
            ServiceError::Runner(format!("proof package chunk {index} not found"))
        })?;
        assembler.insert(chunk).map_err(network_error)?;
    }
    let bytes = assembler.finish().map_err(network_error)?;
    let receipt = verify_downloaded_package(repository, job_id, &bytes)?;
    repository.store_proof_package(job_id, &bytes)?;

    Ok(ProofPackageSyncReport {
        job_id,
        package_hash: manifest.package_hash,
        total_len: manifest.total_len,
        chunk_count: manifest.chunk_count,
        method: receipt.kind().method_name(),
        table_id: receipt.table_id(),
        hand_id: receipt.hand_id(),
        call_seq: receipt.call_seq(),
    })
}

fn verify_downloaded_package(
    repository: &ServiceRepository,
    job_id: Hash,
    bytes: &[u8],
) -> ServiceResult<poker_texas_air::verified_chain::VerificationReceipt> {
    let job = repository
        .job(job_id)
        .ok_or_else(|| ServiceError::Runner("proof package job not found locally".into()))?;
    if job.status != StoredJobStatus::Completed {
        return Err(ServiceError::Runner(
            "proof package can only repair a completed job".into(),
        ));
    }
    let result = job.result.as_ref().ok_or_else(|| {
        ServiceError::Runner("completed proof package job is missing result metadata".into())
    })?;
    if !result.had_prove_task || !result.proof_verified {
        return Err(ServiceError::Runner(
            "completed job does not describe a verified proof".into(),
        ));
    }
    let stored = job.proof.as_ref().ok_or_else(|| {
        ServiceError::Runner("completed proof package job is missing proof metadata".into())
    })?;

    let package = ServiceProofPackage::from_bytes(bytes)?;
    let expected = stored_proof_metadata(package.task())?;
    if stored.task_digest != expected.task_digest
        || stored.pre_state_root != expected.pre_state_root
        || stored.post_state_root != expected.post_state_root
    {
        return Err(ServiceError::Prover(
            "downloaded proof package does not match local job metadata".into(),
        ));
    }

    let receipt = Orchestrator::verify_archived_task_parts(
        package.task(),
        package.archive(),
        package.composition_archive(),
    )
    .map_err(|error| ServiceError::Prover(error.to_string()))?;
    if receipt.table_id() != job.table_id
        || receipt.hand_id() != result.hand_id
        || receipt.call_seq() != result.call_seq
    {
        return Err(ServiceError::Prover(
            "downloaded proof receipt does not match local completed result".into(),
        ));
    }
    Ok(receipt)
}

fn network_error(error: poker_l1::error::PokerL1Error) -> ServiceError {
    ServiceError::Runner(error.to_string())
}

fn request_one_peer<F>(
    peer: SocketAddr,
    timeout: Duration,
    request: &NetworkMessage,
    select: &mut F,
) -> ServiceResult<NetworkMessage>
where
    F: FnMut(&NetworkMessage) -> bool,
{
    let mut stream = TcpStream::connect_timeout(&peer, timeout)
        .map_err(|error| ServiceError::Runner(format!("connect failed: {error}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| ServiceError::Runner(format!("set timeout failed: {error}")))?;
    request_on_stream(&mut stream, request, select)
}

fn request_on_stream<S, F>(
    stream: &mut S,
    request: &NetworkMessage,
    select: &mut F,
) -> ServiceResult<NetworkMessage>
where
    S: Read + Write,
    F: FnMut(&NetworkMessage) -> bool,
{
    let bytes = borsh::to_vec(request)
        .map_err(|error| ServiceError::Runner(format!("encode P2P request: {error}")))?;
    if bytes.len() > MAX_P2P_MESSAGE_BYTES {
        return Err(ServiceError::Runner(
            "P2P request exceeds frame limit".into(),
        ));
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .and_then(|_| stream.flush())
        .map_err(|error| ServiceError::Runner(format!("send P2P request: {error}")))?;

    // A newly accepted zchain connection may receive bounded PEX/header gossip
    // before the direct response. Ignore a small number of unrelated frames.
    for _ in 0..8 {
        let message = read_framed_message(stream)?;
        if select(&message) {
            return Ok(message);
        }
    }
    Err(ServiceError::Runner(
        "peer did not return the requested proof package response".into(),
    ))
}

fn read_framed_message<R: Read>(stream: &mut R) -> ServiceResult<NetworkMessage> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|error| ServiceError::Runner(format!("read P2P frame length: {error}")))?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_P2P_MESSAGE_BYTES {
        return Err(ServiceError::Runner(format!(
            "invalid P2P response frame length {len}"
        )));
    }
    let mut bytes = vec![0u8; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| ServiceError::Runner(format!("read P2P frame body: {error}")))?;
    NetworkMessage::try_from_slice(&bytes)
        .map_err(|error| ServiceError::Runner(format!("decode P2P response: {error}")))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    struct ScriptedStream {
        incoming: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(incoming: Vec<u8>) -> Self {
            Self {
                incoming: Cursor::new(incoming),
                written: Vec::new(),
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.incoming.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn tcp_peer() -> TcpProofPackagePeer {
        TcpProofPackagePeer::new(vec![peer(10001), peer(10002)]).unwrap()
    }

    fn frame(message: &NetworkMessage) -> Vec<u8> {
        let bytes = borsh::to_vec(message).unwrap();
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
        out
    }

    #[test]
    fn failover_continues_after_missing_response() {
        let client = tcp_peer();
        let result = client
            .request_from_first_available("test", |address| {
                if address == peer(10001) {
                    Ok(None)
                } else {
                    Ok(Some(7u32))
                }
            })
            .unwrap();
        assert_eq!(result, Some(7));
    }

    #[test]
    fn failover_continues_after_invalid_peer_error() {
        let client = tcp_peer();
        let mut attempts = 0;
        let result = client
            .request_from_first_available("test", |address| {
                if address == peer(10001) {
                    attempts += 1;
                    Err(ServiceError::Runner("bad manifest".into()))
                } else {
                    Ok(Some(9u32))
                }
            })
            .unwrap();
        assert_eq!(result, Some(9));
        assert_eq!(attempts, DEFAULT_PEER_ATTEMPTS);
    }

    #[test]
    fn retry_configuration_rejects_zero_values() {
        assert!(
            TcpProofPackagePeer::with_timeout_and_attempts(
                vec![peer(10001)],
                Duration::from_secs(1),
                0,
            )
            .is_err()
        );
        assert!(
            TcpProofPackagePeer::with_timeout_and_attempts(vec![peer(10001)], Duration::ZERO, 1,)
                .is_err()
        );
    }

    #[test]
    fn failover_returns_none_when_every_peer_is_missing() {
        let result: Option<u32> = tcp_peer()
            .request_from_first_available("test", |_| Ok(None))
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn failover_reports_errors_when_no_peer_succeeds() {
        let error = tcp_peer()
            .request_from_first_available::<u32, _>("chunk", |address| {
                if address == peer(10001) {
                    Ok(None)
                } else {
                    Err(ServiceError::Runner("hash mismatch".into()))
                }
            })
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("1 missing"), "{message}");
        assert!(message.contains("hash mismatch"), "{message}");
        assert!(message.contains("10002"), "{message}");
    }

    #[test]
    fn request_stream_skips_unrelated_frames_and_writes_canonical_request() {
        let request = NetworkMessage::RequestProofPackageManifest([3u8; 32]);
        let expected = NetworkMessage::ResponseProofPackageManifest(None);
        let mut incoming = frame(&NetworkMessage::PeerExchange(Vec::new()));
        incoming.extend(frame(&expected));
        let mut stream = ScriptedStream::new(incoming);

        let response = request_on_stream(&mut stream, &request, &mut |message| {
            matches!(message, NetworkMessage::ResponseProofPackageManifest(_))
        })
        .unwrap();
        assert!(matches!(
            response,
            NetworkMessage::ResponseProofPackageManifest(None)
        ));

        let mut written = Cursor::new(stream.written);
        let decoded = read_framed_message(&mut written).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::RequestProofPackageManifest(job_id) if job_id == [3u8; 32]
        ));
    }

    #[test]
    fn framed_reader_rejects_zero_and_oversized_lengths() {
        for length in [0usize, MAX_P2P_MESSAGE_BYTES + 1] {
            let mut input = Cursor::new((length as u32).to_be_bytes().to_vec());
            let error = read_framed_message(&mut input).unwrap_err().to_string();
            assert!(
                error.contains("invalid P2P response frame length"),
                "{error}"
            );
        }
    }

    #[test]
    fn framed_reader_rejects_truncated_length_and_body() {
        let mut short_length = Cursor::new(vec![0, 0]);
        let error = read_framed_message(&mut short_length)
            .unwrap_err()
            .to_string();
        assert!(error.contains("read P2P frame length"), "{error}");

        let mut short_body = Cursor::new(vec![0, 0, 0, 4, 1, 2]);
        let error = read_framed_message(&mut short_body)
            .unwrap_err()
            .to_string();
        assert!(error.contains("read P2P frame body"), "{error}");
    }

    #[test]
    fn framed_reader_rejects_malformed_borsh() {
        let mut malformed = vec![0, 0, 0, 1, 0xff];
        let error = read_framed_message(&mut Cursor::new(&mut malformed))
            .unwrap_err()
            .to_string();
        assert!(error.contains("decode P2P response"), "{error}");
    }
}
