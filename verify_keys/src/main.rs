use std::collections::HashMap;
use std::fs;

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
    construct_setup_parameters_per_crt_prime, verify_knowledge_of_decryption_key_proofs,
    KnowledgeOfDiscreteLogUCProof, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
};
use class_groups::{CompactIbqf, EquivalenceClass, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};
use group::GroupElement;

type PartyID = u16;
type KeyAndProof = (
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    KnowledgeOfDiscreteLogUCProof,
);
type KeysAndProofsArr = [KeyAndProof; MAX_PRIMES];

fn main() {
    let setup_params = construct_setup_parameters_per_crt_prime(
        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    )
    .expect("setup params construction");

    let lang_params = construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
        std::array::from_fn(|i| &setup_params[i]),
    )
    .expect("lang params construction");

    let mut decode_failures: Vec<(PartyID, String)> = Vec::new();
    let mut keys_and_proofs_compact: HashMap<PartyID, KeysAndProofsArr> = HashMap::new();

    for i in 1u16..=74 {
        let path = format!("/tmp/cgkeys/v_{}.bin", i);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        match bcs::from_bytes::<KeysAndProofsArr>(&bytes) {
            Ok(arr) => {
                keys_and_proofs_compact.insert(i, arr);
            }
            Err(e) => {
                decode_failures.push((i, format!("{e}")));
            }
        }
    }

    println!("=== BCS DECODE ===");
    println!(
        "decoded: {}/{} (failures: {})",
        keys_and_proofs_compact.len(),
        74,
        decode_failures.len()
    );
    for (pid, e) in &decode_failures {
        println!("  v{pid}: {e}");
    }

    // Convert CompactIbqf -> EquivalenceClass per CRT prime, mirroring
    // class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::instantiate_encryption_keys_per_crt_prime
    let mut instantiation_failures: Vec<PartyID> = Vec::new();
    let mut keys_and_proofs_eq: HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    > = HashMap::new();

    for (pid, arr) in keys_and_proofs_compact.into_iter() {
        let mut converted: Vec<(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        )> = Vec::with_capacity(MAX_PRIMES);
        let mut bad = false;
        for i in 0..MAX_PRIMES {
            let (compact, proof) = arr[i].clone();
            match EquivalenceClass::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                compact,
                setup_params[i].equivalence_class_public_parameters(),
            ) {
                Ok(ec) => converted.push((ec, proof)),
                Err(e) => {
                    println!("v{pid} crt={i} EquivalenceClass::new error: {e:?}");
                    bad = true;
                    break;
                }
            }
        }
        if bad {
            instantiation_failures.push(pid);
        } else {
            let arr_eq: [(EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, KnowledgeOfDiscreteLogUCProof); MAX_PRIMES] =
                converted.try_into().unwrap_or_else(|_| panic!("MAX_PRIMES mismatch"));
            keys_and_proofs_eq.insert(pid, arr_eq);
        }
    }

    println!("=== INSTANTIATE EquivalenceClass ===");
    println!(
        "instantiated: {} (failures: {:?})",
        keys_and_proofs_eq.len(),
        instantiation_failures
    );

    // Run verify_knowledge_of_decryption_key_proofs
    let pre_invalid: Vec<PartyID> = decode_failures
        .iter()
        .map(|(p, _)| *p)
        .chain(instantiation_failures.iter().copied())
        .collect();

    let result = verify_knowledge_of_decryption_key_proofs(
        lang_params,
        pre_invalid.clone(),
        keys_and_proofs_eq,
    );

    println!("=== verify_knowledge_of_decryption_key_proofs ===");
    match result {
        Ok((malicious, valid_keys)) => {
            println!("malicious_parties (count={}):", malicious.len());
            for p in &malicious {
                println!("  v{p}");
            }
            println!("valid_keys (count={}):", valid_keys.len());
            let mut ids: Vec<_> = valid_keys.keys().copied().collect();
            ids.sort();
            for p in &ids {
                println!("  v{p} OK");
            }
        }
        Err(e) => {
            println!("verify returned Err: {e:?}");
        }
    }
}
