//! cairo-bridge-poc driver.
//!
//! 1. Runs the Rust mirror of `verify_min` to obtain the expected FRI
//!    last-layer constant and Merkle root; embeds them into the Cairo source.
//! 2. `scarb build`s all 9 executables.
//! 3. Runs each executable in cairo-vm (proof_mode, all_cairo_stwo layout,
//!    no trace padding) and records steps + builtin instance counts.
//! 4. Proves + verifies `prog_verify_min` with stwo-cairo 1.2.2
//!    (Blake2s and Poseidon252 channel variants, official 96-bit params),
//!    recording wall-clock times and serialized proof sizes.
//! 5. Cross-checks with the official `scarb prove` / `scarb verify` toolchain.

mod mirror;

use anyhow::{bail, Context, Result};
use cairo_lang_executable::executable::{EntryPointKind, Executable};
use cairo_lang_runner::{build_hints_dict, Arg, CairoHintProcessor};
use cairo_vm::cairo_run::cairo_run_program_with_initial_scope;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::Felt252;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const PROBE_ROOT: &str = "/Users/mac/projects/zchain/cairo-bridge-poc";

const PROGS: &[&str] = &[
    "prog_baseline",
    "prog_hades",
    "prog_m31_add",
    "prog_m31_mul",
    "prog_qm31_mul",
    "prog_fri_fold",
    "prog_channel",
    "prog_merkle",
    "prog_verify_min",
];

fn sh(cmd: &str, args: &[&str], cwd: &Path, log: &mut String) -> Result<String> {
    use std::process::Command;
    let out = Command::new(if cmd == "scarb" { "/Users/mac/.local/bin/scarb" } else { cmd })
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("spawn {cmd} {args:?}"))?;
    let text = format!(
        "--- {} {:?} (cwd={}) ---\nexit={}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
        cmd,
        args,
        cwd.display(),
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    log.push_str(&text);
    if !out.status.success() {
        bail!("{cmd} {args:?} failed:\n{text}");
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn embed_consts() -> Result<()> {
    let m = mirror::run();
    println!("mirror: last_layer_c = {:?}", m.last_layer_c);
    println!("mirror: merkle_root  = {:#x}", m.merkle_root);
    println!("mirror: checksum     = {:#x}", m.checksum);

    let lib = PathBuf::from(PROBE_ROOT).join("crates/base/src/lib.cairo");
    let mut src = fs::read_to_string(&lib)?;
    // Replace the line tagged `// EMBED_C` and `// EMBED_ROOT`.
    let mut out = String::new();
    let mut replaced_c = false;
    let mut replaced_root = false;
    for line in src.lines() {
        let l = if line.contains("// EMBED_C") {
            replaced_c = true;
            format!(
                "        [{:#08x}, {:#08x}, {:#08x}, {:#08x}] // EMBED_C (driver mirror)",
                m.last_layer_c[0], m.last_layer_c[1], m.last_layer_c[2], m.last_layer_c[3]
            )
        } else if line.contains("// EMBED_ROOT") {
            replaced_root = true;
            format!("        {:#x} // EMBED_ROOT (driver mirror)", m.merkle_root)
        } else {
            line.to_string()
        };
        out.push_str(&l);
        out.push('\n');
    }
    if !replaced_c || !replaced_root {
        bail!("embed markers not found in lib.cairo");
    }
    src = out;
    fs::write(&lib, src)?;
    println!("embedded constants into crates/base/src/lib.cairo");
    Ok(())
}

struct RunResult {
    n_steps: usize,
    memory_holes: usize,
    builtins: String,
    output: Option<Felt252>,
    elapsed: std::time::Duration,
}

fn run_executable(exe_path: &Path) -> Result<RunResult> {
    let file = fs::File::open(exe_path)?;
    let executable: Executable = serde_json::from_reader(file)?;

    let entrypoint = executable
        .entrypoints
        .iter()
        .find(|e| matches!(e.kind, EntryPointKind::Standalone))
        .context("no standalone entrypoint")?
        .clone();

    let (hints, string_to_hint) = build_hints_dict(&executable.program.hints);
    let data: Vec<MaybeRelocatable> = executable
        .program
        .bytecode
        .iter()
        .map(|bi| MaybeRelocatable::Int(Felt252::from(bi)))
        .collect();

    let program = Program::new_for_proof(
        entrypoint.builtins.clone(),
        data,
        entrypoint.offset,
        entrypoint.offset + 4,
        hints,
        Default::default(),
        Default::default(),
        vec![],
        None,
    )?;

    let hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(Vec::new())]],
        string_to_hint,
        starknet_state: cairo_lang_runner::StarknetState::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: vec![],
        panic_traceback: vec![],
    };

    let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
        trace_enabled: true,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        fill_holes: true,
        proof_mode: true,
        disable_trace_padding: true,
        ..Default::default()
    };

    let t0 = Instant::now();
    let mut hint_processor = hint_processor;
    let runner = cairo_run_program_with_initial_scope(
        &program,
        &cairo_run_config,
        &mut hint_processor,
        ExecutionScopes::new(),
    )?;
    let elapsed = t0.elapsed();

    let resources = runner.get_execution_resources()?;
    let builtins = format!("{:?}", resources.builtin_instance_counter);
    let output: Option<Felt252> = None; // output-builtin read omitted (anti-DCE checksum verified via proving)

    Ok(RunResult {
        n_steps: resources.n_steps,
        memory_holes: resources.n_memory_holes,
        builtins,
        output,
        elapsed,
    })
}

fn prove_and_verify(
    prover_input: stwo_cairo_adapter::ProverInput,
    tag: &str,
    log: &mut String,
) -> Result<()> {
    use cairo_air::utils::{serialize_proof_to_file, ProofFormat};
    use stwo::core::pcs::PcsConfig;
    use stwo::core::fri::FriConfig;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
    use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
    use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
    use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};
    use stwo_cairo_serialize::CairoSerialize;

    let params_of = |hash| ProverParameters {
        channel_hash: hash,
        channel_salt: 0,
        pcs_config: PcsConfig {
            pow_bits: 26,
            fri_config: FriConfig {
                log_last_layer_degree_bound: 0,
                log_blowup_factor: 1,
                n_queries: 70,
                fold_step: 1,
            },
            lifting_log_size: None,
        },
        preprocessed_trace: PreProcessedTraceVariant::Canonical,
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: false,
    };

    macro_rules! run_channel {
        ($mc:ty, $hash:expr, $name:literal) => {{
            let name: &str = $name;
            let params = params_of($hash);
            let input = prover_input.clone();
            let t0 = Instant::now();
            let proof = prove_cairo::<$mc>(input, params)
                .map_err(|e| anyhow::anyhow!("prove ({tag}->{name}) failed: {e:?}"))?;
            let prove_time = t0.elapsed();

            let t1 = Instant::now();
            cairo_air::verifier::verify_cairo_ex::<$mc>(proof.clone().into(), false)
                .map_err(|e| anyhow::anyhow!("verify ({tag}->{name}) failed: {e:?}"))?;
            let verify_time = t1.elapsed();

            // cairo_serde felt count == SHARP / on-chain-facing proof size.
            // CairoSerialize demands all 11 segment ranges; fill the unused
            // builtins with empty ranges (serialization-only view; verify()
            // above used the original claim).
            let mut serde_view = proof.clone();
            let empty = cairo_air::air::SegmentRange {
                start_ptr: cairo_air::air::MemorySmallValue { id: 0, value: 0 },
                stop_ptr: cairo_air::air::MemorySmallValue { id: 0, value: 0 },
            };
            let segs = &mut serde_view.claim.public_data.public_memory.public_segments;
            if segs.pedersen.is_none() { segs.pedersen = Some(empty.clone()); }
            if segs.range_check_128.is_none() { segs.range_check_128 = Some(empty.clone()); }
            if segs.ecdsa.is_none() { segs.ecdsa = Some(empty.clone()); }
            if segs.bitwise.is_none() { segs.bitwise = Some(empty.clone()); }
            if segs.ec_op.is_none() { segs.ec_op = Some(empty.clone()); }
            if segs.keccak.is_none() { segs.keccak = Some(empty.clone()); }
            if segs.poseidon.is_none() { segs.poseidon = Some(empty.clone()); }
            if segs.range_check_96.is_none() { segs.range_check_96 = Some(empty.clone()); }
            if segs.add_mod.is_none() { segs.add_mod = Some(empty.clone()); }
            if segs.mul_mod.is_none() { segs.mul_mod = Some(empty); }
            let mut felts: Vec<starknet_ff::FieldElement> = Vec::new();
            CairoSerialize::serialize(&serde_view, &mut felts);
            let serde_felts = felts.len();

            let json_path = format!("{PROBE_ROOT}/logs/proof_{tag}_{name}.json");
            serialize_proof_to_file(
                &proof,
                Path::new(&json_path),
                ProofFormat::Json,
            )?;
            let json_bytes = fs::metadata(&json_path)?.len();

            let bin_path = format!("{PROBE_ROOT}/logs/proof_{tag}_{name}.bin");
            serialize_proof_to_file(&proof, Path::new(&bin_path), ProofFormat::Binary)?;
            let bin_bytes = fs::metadata(&bin_path)?.len();

            let line = format!(
                "[{tag}] params={name} prove={prove_time:?} verify={verify_time:?} cairo_serde_felts={serde_felts} json_bytes={json_bytes} binary_bz2_bytes={bin_bytes}"
            );
            println!("{line}");
            log.push_str(&line);
            log.push('\n');
        }};
    }

    let only = std::env::var("BRIDGE_CHANNEL").unwrap_or_default();
    if only.is_empty() || only == "blake2s" {
        run_channel!(Blake2sMerkleChannel, ChannelHash::Blake2s, "blake2s_pow26_q70");
    }
    if only.is_empty() || only == "m31" {
        run_channel!(Blake2sM31MerkleChannel, ChannelHash::Blake2sM31, "blake2s_m31_pow26_q70");
    }
    if only.is_empty() || only == "poseidon" {
        run_channel!(Poseidon252MerkleChannel, ChannelHash::Poseidon252, "poseidon252_pow26_q70");
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut log = String::new();
    fs::create_dir_all(Path::new(PROBE_ROOT).join("logs"))?;

    println!("== step 1: mirror + embed ==");
    embed_consts()?;

    println!("== step 2: scarb build ==");
    let build_out = sh("scarb", &["build"], Path::new(PROBE_ROOT), &mut log)?;
    log.push_str(&build_out);
    println!("scarb build ok");

    println!("== step 3: run all executables in cairo-vm (proof mode) ==");
    let mut verify_min_input: Option<stwo_cairo_adapter::ProverInput> = None;
    for name in PROGS {
        let exe = PathBuf::from(format!("{PROBE_ROOT}/target/dev/{name}.executable.json"));
        match run_executable(&exe) {
            Ok(r) => {
                println!(
                    "{name}: steps={} mem_holes={} vm_time={:.1?} builtins={} output={:?}",
                    r.n_steps, r.memory_holes, r.elapsed, r.builtins, r.output
                );
                log.push_str(&format!(
                    "{name}: steps={} mem_holes={} vm_time={:?} builtins={} output={:?}\n",
                    r.n_steps, r.memory_holes, r.elapsed, r.builtins, r.output
                ));
                if *name == "prog_verify_min" {
                    // Re-run to obtain ProverInput (run_executable consumed the runner).
                    verify_min_input = Some(rerun_for_input(&exe)?);
                }
            }
            Err(e) => {
                println!("{name}: FAILED: {e:#}");
                log.push_str(&format!("{name}: FAILED: {e:#}\n"));
            }
        }
    }

    println!("== step 4: stwo-cairo prove + verify (prog_verify_min) ==");
    if let Some(input) = verify_min_input {
        if let Err(e) = prove_and_verify(input, "prog_verify_min", &mut log) {
            println!("prove/verify FAILED: {e:#}");
            log.push_str(&format!("prove/verify FAILED: {e:#}\n"));
        }
    }

    fs::write(Path::new(PROBE_ROOT).join("logs/driver_raw.txt"), &log)?;
    println!("wrote ../logs/driver_raw.txt (pre-scarb-CLI snapshot)");

    println!("== step 5: official scarb prove / scarb verify ==");
    let prov_log = sh(
        "scarb",
        &[
            "prove",
            "-p",
            "prog_verify_min",
            "--execute",
            "--print-resource-usage",
        ],
        Path::new(PROBE_ROOT),
        &mut log,
    )?;
    println!("{prov_log}");
    let proof_json = sh(
        "sh",
        &["-c", "ls -t target/execute/prog_verify_min/*/proof/proof.json | head -1"],
        Path::new(PROBE_ROOT),
        &mut log,
    )?
    .trim()
    .to_string();
    let ver_log = sh(
        "scarb",
        &["verify", "-p", "prog_verify_min", "--proof-file", &proof_json],
        Path::new(PROBE_ROOT),
        &mut log,
    )?;
    println!("{ver_log}");

    fs::write(Path::new(PROBE_ROOT).join("logs/driver_raw.txt"), &log)?;
    println!("wrote ../logs/driver_raw.txt");
    Ok(())
}

/// Run once more, converting the runner into a stwo ProverInput via the
/// official adapter.
fn rerun_for_input(exe_path: &Path) -> Result<stwo_cairo_adapter::ProverInput> {
    let file = fs::File::open(exe_path)?;
    let executable: Executable = serde_json::from_reader(file)?;
    let entrypoint = executable
        .entrypoints
        .iter()
        .find(|e| matches!(e.kind, EntryPointKind::Standalone))
        .context("no standalone entrypoint")?
        .clone();
    let (hints, string_to_hint) = build_hints_dict(&executable.program.hints);
    let data: Vec<MaybeRelocatable> = executable
        .program
        .bytecode
        .iter()
        .map(|bi| MaybeRelocatable::Int(Felt252::from(bi)))
        .collect();
    let program = Program::new_for_proof(
        entrypoint.builtins.clone(),
        data,
        entrypoint.offset,
        entrypoint.offset + 4,
        hints,
        Default::default(),
        Default::default(),
        vec![],
        None,
    )?;
    let hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(Vec::new())]],
        string_to_hint,
        starknet_state: cairo_lang_runner::StarknetState::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: vec![],
        panic_traceback: vec![],
    };
    let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
        trace_enabled: true,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        fill_holes: true,
        proof_mode: true,
        disable_trace_padding: true,
        ..Default::default()
    };
    let mut hint_processor = hint_processor;
    let runner = cairo_run_program_with_initial_scope(
        &program,
        &cairo_run_config,
        &mut hint_processor,
        ExecutionScopes::new(),
    )?;
    let mut input = stwo_cairo_adapter::adapter::adapt(&runner)?;
    // The adapter hardcodes PublicSegmentContext::bootloader_context() (all 11
    // layout segments), which mismatches scarb `#[executable]` programs that
    // only declare the builtins they use. Rebuild the context from the
    // executable's own builtin list (same approach as the official
    // `scarb prove` pipeline).
    input.public_segment_context = stwo_cairo_adapter::PublicSegmentContext::new(&entrypoint.builtins);
    Ok(input)
}
