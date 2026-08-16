//! replay_reconfig — reproduce a failing reconfiguration MPC round outside of
//! a live validator using the `/tmp/ika_debug/<sid>_*.bin` blobs the
//! `mainnet-v1.1.8-debug` branch dumps.
//!
//! Usage:
//!   replay_reconfig --dump-dir /tmp/ika_debug --session <sid_hex> [--party-id 1] [--target-round 2]
//!
//! Or via positional args:
//!   replay_reconfig <dump_dir> <sid_hex> [<party_id>] [<target_round>]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    KnowledgeOfDiscreteLogUCProof, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
};
use class_groups::{
    CompactIbqf, SecretKeyShareSizedInteger,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::secp256k1::SCALAR_LIMBS;
use group::PartyID;
use mpc::{AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
use serde::Deserialize;

/// Mirror of `mpc::guaranteed_output_delivery::Message<M>` — fields private
/// upstream so we redeclare with matching field order for BCS positional decode.
#[derive(Deserialize)]
enum WrappedMpcMessage<M> {
    MessageWithMetadata(WrappedMessageWithMetadata<M>),
    ThresholdNotReached {
        consensus_round_number: u64,
    },
}

/// Mirror of `mpc::guaranteed_output_delivery::MessageWithMetadata<M>`.
#[derive(Deserialize)]
struct WrappedMessageWithMetadata<M> {
    mpc_round_number: u64,
    inactive_or_ignored_senders_by_round: HashMap<u64, Vec<PartyID>>,
    malicious_parties: Vec<PartyID>,
    message: M,
}
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use twopc_mpc::decentralized_party::reconfiguration::{Message, Party, PublicInput};

type CgDkgPublicOutput = class_groups::dkg::PublicOutput<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
>;

type EncryptionKeysAndProofsMap = HashMap<
    PartyID,
    [(
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        KnowledgeOfDiscreteLogUCProof,
    ); MAX_PRIMES],
>;

#[derive(Debug)]
struct Args {
    dump_dir: PathBuf,
    session_id_hex: String,
    party_id: PartyID,
    target_round: u8,
}

fn parse_args() -> Args {
    let mut dump_dir: Option<PathBuf> = None;
    let mut session_id_hex: Option<String> = None;
    let mut party_id: PartyID = 1;
    let mut target_round: u8 = 2;
    let mut positional: Vec<String> = Vec::new();

    let mut iter = std::env::args().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dump-dir" => dump_dir = Some(PathBuf::from(iter.next().expect("--dump-dir VALUE"))),
            "--session" => session_id_hex = Some(iter.next().expect("--session VALUE")),
            "--party-id" => {
                party_id = iter.next().expect("--party-id VALUE").parse().expect("party id u16")
            }
            "--target-round" => {
                target_round = iter
                    .next()
                    .expect("--target-round VALUE")
                    .parse()
                    .expect("target-round u8")
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: replay_reconfig [--dump-dir DIR] [--session SID_HEX] [--party-id N] [--target-round R]\n\
                          replay_reconfig DIR SID_HEX [PARTY_ID] [TARGET_ROUND]"
                );
                std::process::exit(0);
            }
            _ if !arg.starts_with("--") => positional.push(arg),
            _ => {
                eprintln!("unknown arg: {arg}");
                std::process::exit(2);
            }
        }
    }

    if dump_dir.is_none() {
        if let Some(p) = positional.first() {
            dump_dir = Some(PathBuf::from(p));
        }
    }
    if session_id_hex.is_none() {
        if let Some(s) = positional.get(1) {
            session_id_hex = Some(s.clone());
        }
    }
    if let Some(p) = positional.get(2) {
        party_id = p.parse().expect("positional party id u16");
    }
    if let Some(r) = positional.get(3) {
        target_round = r.parse().expect("positional target_round u8");
    }

    Args {
        dump_dir: dump_dir.unwrap_or_else(|| PathBuf::from("/tmp/ika_debug")),
        session_id_hex: session_id_hex.expect("session id (hex) is required"),
        party_id,
        target_round,
    }
}

fn read_pubinput(dir: &Path, sid: &str, name: &str) -> Option<Vec<u8>> {
    let path = dir.join(format!("{sid}_pubinput_{name}.bin"));
    if path.exists() {
        Some(fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}")))
    } else {
        None
    }
}

fn must_read_pubinput(dir: &Path, sid: &str, name: &str) -> Vec<u8> {
    read_pubinput(dir, sid, name)
        .unwrap_or_else(|| panic!("missing pubinput file: {sid}_pubinput_{name}.bin"))
}

fn build_public_input(dump_dir: &Path, sid: &str) -> PublicInput {
    let current_access_structure_bcs = must_read_pubinput(dump_dir, sid, "current_access_structure");
    let upcoming_access_structure_bcs = must_read_pubinput(dump_dir, sid, "upcoming_access_structure");
    let current_tangible_party_id_to_upcoming_bcs =
        must_read_pubinput(dump_dir, sid, "current_tangible_party_id_to_upcoming");
    let current_encryption_keys_bcs = must_read_pubinput(dump_dir, sid, "current_encryption_keys");
    let upcoming_encryption_keys_bcs = must_read_pubinput(dump_dir, sid, "upcoming_encryption_keys");

    let current_access_structure: WeightedThresholdAccessStructure =
        bcs::from_bytes(&current_access_structure_bcs).expect("decode current_access_structure");
    let upcoming_access_structure: WeightedThresholdAccessStructure =
        bcs::from_bytes(&upcoming_access_structure_bcs).expect("decode upcoming_access_structure");
    let current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>> =
        bcs::from_bytes(&current_tangible_party_id_to_upcoming_bcs)
            .expect("decode current_tangible_party_id_to_upcoming");
    let current_encryption_keys: EncryptionKeysAndProofsMap =
        bcs::from_bytes(&current_encryption_keys_bcs).expect("decode current_encryption_keys");
    let upcoming_encryption_keys: EncryptionKeysAndProofsMap =
        bcs::from_bytes(&upcoming_encryption_keys_bcs).expect("decode upcoming_encryption_keys");

    println!(
        "[pubinput] current parties={} threshold={}, upcoming parties={} threshold={}, current_keys={} upcoming_keys={}",
        current_access_structure.party_to_weight.len(),
        current_access_structure.threshold,
        upcoming_access_structure.party_to_weight.len(),
        upcoming_access_structure.threshold,
        current_encryption_keys.len(),
        upcoming_encryption_keys.len(),
    );

    let v2 = read_pubinput(dump_dir, sid, "network_dkg_public_output_v2");
    let v1 = read_pubinput(dump_dir, sid, "network_dkg_public_output_v1");
    let latest_reconfig = read_pubinput(dump_dir, sid, "latest_reconfiguration_public_output");

    match (v2, v1, latest_reconfig) {
        (Some(v2_bytes), _, Some(latest_bytes)) => {
            println!("[pubinput] mode = V2 + latest_reconfiguration_public_output");
            // ika passes:
            //   public_output: twopc_mpc::dkg::PublicOutput  (decoded from v2 bytes)
            //   .into() -> class_groups::dkg::PublicOutput
            //   public_output: reconfiguration::PublicOutput (decoded from latest bytes)
            let dkg_pub_output_2pc: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(&v2_bytes).expect("decode network_dkg_public_output_v2 (twopc_mpc::dkg::PublicOutput)");
            let dkg_pub_output_cg: CgDkgPublicOutput = dkg_pub_output_2pc.into();
            let reconfig_pub_output: <Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(&latest_bytes).expect("decode latest_reconfiguration_public_output");
            PublicInput::new_from_reconfiguration_output(
                &current_access_structure,
                upcoming_access_structure,
                current_encryption_keys,
                upcoming_encryption_keys,
                current_tangible_party_id_to_upcoming,
                dkg_pub_output_cg,
                reconfig_pub_output,
            )
            .expect("PublicInput::new_from_reconfiguration_output")
        }
        (Some(v2_bytes), _, None) => {
            println!("[pubinput] mode = V2 (no latest reconfiguration output)");
            let dkg_pub_output_2pc: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(&v2_bytes).expect("decode network_dkg_public_output_v2");
            PublicInput::new_from_dkg_output(
                &current_access_structure,
                upcoming_access_structure,
                current_encryption_keys,
                upcoming_encryption_keys,
                current_tangible_party_id_to_upcoming,
                dkg_pub_output_2pc,
            )
            .expect("PublicInput::new_from_dkg_output")
        }
        (None, Some(v1_bytes), Some(latest_bytes)) => {
            println!("[pubinput] mode = V1 + latest_reconfiguration_public_output");
            let dkg_pub_output_cg: CgDkgPublicOutput =
                bcs::from_bytes(&v1_bytes).expect("decode network_dkg_public_output_v1");
            let reconfig_pub_output: <Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(&latest_bytes).expect("decode latest_reconfiguration_public_output");
            PublicInput::new_from_reconfiguration_output(
                &current_access_structure,
                upcoming_access_structure,
                current_encryption_keys,
                upcoming_encryption_keys,
                current_tangible_party_id_to_upcoming,
                dkg_pub_output_cg,
                reconfig_pub_output,
            )
            .expect("PublicInput::new_from_reconfiguration_output (v1)")
        }
        (None, None, _) => {
            panic!("missing both network_dkg_public_output_v1.bin and network_dkg_public_output_v2.bin");
        }
        (None, Some(_), None) => {
            panic!(
                "found V1 dkg public output but no latest_reconfiguration_public_output — \
                 V1 path requires a previous reconfiguration"
            );
        }
    }
}

/// Returns the MPC round (1-indexed) that this protocol message belongs to.
fn msg_round(m: &Message) -> u8 {
    match m {
        Message::DealRandomizerContributionAndProveCoefficientCommitments { .. } => 1,
        Message::VerifiedRandomizerDealers(_) => 2,
        Message::ThresholdDecryptShares { .. } => 3,
    }
}

fn collect_messages(dump_dir: &Path, sid: &str) -> HashMap<u8, HashMap<PartyID, Message>> {
    // Filename patterns produced by the debug branch:
    //   <sid>_msg_p<sender>_mpcr<R>.bin   (reconfig)
    //   <sid>_msg_p<sender>.bin           (other protocols, fallback)
    // We trust the decoded Message variant for round bucketing; sender comes
    // from the filename.
    let prefix = format!("{sid}_msg_p");
    let mut by_round: HashMap<u8, HashMap<PartyID, Message>> = HashMap::new();
    let mut decode_failures: Vec<(String, String)> = Vec::new();

    let entries = fs::read_dir(dump_dir).unwrap_or_else(|e| panic!("read {dump_dir:?}: {e}"));
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        if !name_str.starts_with(&prefix) || !name_str.ends_with(".bin") {
            continue;
        }
        let rest = &name_str[prefix.len()..name_str.len() - 4]; // strip prefix and ".bin"
        let sender_str = rest.split('_').next().unwrap_or("");
        let sender: PartyID = match sender_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let bytes = fs::read(entry.path()).unwrap_or_else(|e| panic!("read {:?}: {e}", entry.path()));
        // The validator stores `mpc::Message<<Party as Party>::Message>` (the
        // GOD-delivery wrapper carrying mpc_round_number etc.), not the inner
        // protocol message directly.
        let wrapped: WrappedMpcMessage<Message> = match bcs::from_bytes(&bytes) {
            Ok(m) => m,
            Err(e) => {
                decode_failures.push((name_str, format!("{e}")));
                continue;
            }
        };
        let (round_from_wrapper, inner) = match wrapped {
            WrappedMpcMessage::MessageWithMetadata(m) => (m.mpc_round_number, m.message),
            WrappedMpcMessage::ThresholdNotReached { consensus_round_number } => {
                println!(
                    "[messages] {name_str} is a ThresholdNotReached marker (consensus_round={consensus_round_number}); skipping"
                );
                continue;
            }
        };
        let round_from_variant = msg_round(&inner);
        let mpc_round = round_from_wrapper as u8;
        if mpc_round != round_from_variant {
            println!(
                "[messages] {name_str} mpc_round_number={mpc_round} disagrees with inner variant round={round_from_variant}; using wrapper value"
            );
        }
        let bucket = by_round.entry(mpc_round).or_default();
        bucket.entry(sender).or_insert(inner);
    }

    println!("[messages] decoded files into MPC rounds:");
    let mut rounds: Vec<_> = by_round.keys().copied().collect();
    rounds.sort();
    for r in rounds {
        println!("  round {r}: {} unique senders", by_round[&r].len());
    }
    if !decode_failures.is_empty() {
        println!("[messages] {} files failed to decode as Message:", decode_failures.len());
        for (n, e) in &decode_failures {
            println!("  {n}: {e}");
        }
    }

    by_round
}

fn parse_session_id(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("session id hex");
    assert_eq!(bytes.len(), 32, "session id must be 32 bytes hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn main() {
    let args = parse_args();
    println!("[args] {args:?}");

    let session_id_bytes = parse_session_id(&args.session_id_hex);
    let session_id = CommitmentSizedNumber::from_le_slice(&session_id_bytes);

    let public_input = build_public_input(&args.dump_dir, &args.session_id_hex);
    let by_round = collect_messages(&args.dump_dir, &args.session_id_hex);

    // Build messages: Vec<HashMap<PartyID, Message>> with rounds [1..target_round-1]
    let mut messages: Vec<HashMap<PartyID, Message>> = Vec::new();
    for r in 1..args.target_round {
        match by_round.get(&r) {
            Some(m) => messages.push(m.clone()),
            None => panic!("missing messages for MPC round {r}; cannot replay round {}", args.target_round),
        }
    }
    println!(
        "[advance] replaying round {} for party {} with {} prior round(s) of messages",
        args.target_round,
        args.party_id,
        messages.len()
    );

    // For round 2 (and round 1), private_input doesn't need to contain real
    // decryption-key shares — prepare_advance just unwraps the Option, and
    // round 2's body doesn't touch the values. For round 3+, you'd need real
    // decryption-key shares.
    let private_input: Option<HashMap<PartyID, SecretKeyShareSizedInteger>> =
        Some(HashMap::new());

    // Borrow the access structure out of the public input. PublicInput stores
    // current_access_structure inside class_groups_public_input; reconstruct
    // it from the dumped pubinput file (we already loaded it above for logging).
    let cas_bcs = must_read_pubinput(&args.dump_dir, &args.session_id_hex, "current_access_structure");
    let current_access_structure: WeightedThresholdAccessStructure =
        bcs::from_bytes(&cas_bcs).expect("redecode current_access_structure");

    // Deterministic RNG so reruns produce identical results.
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let result = Party::advance(
        session_id,
        args.party_id,
        &current_access_structure,
        messages,
        private_input,
        &public_input,
        &mut rng,
    );

    println!("=== advance result ===");
    match result {
        Ok(round_result) => {
            println!("Ok variant (no error). Outcome:");
            // We don't re-print the message bytes; just structure.
            println!("{:?}", std::mem::discriminant(&round_result));
        }
        Err(e) => {
            println!("Err: {e}");
            println!("Debug: {e:?}");
        }
    }
}
