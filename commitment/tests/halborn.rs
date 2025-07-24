// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#[cfg(test)]
mod tests {
    use commitment::GroupsPublicParametersAccessors;
    use crypto_bigint::U256;
    use group::CyclicGroupElement;
    use group::HashToGroup;
    use rand_core::OsRng;

    use group::{
        secp256k1::{self},
        GroupElement, Samplable,
    };

    use commitment::{
        pedersen::{self, Pedersen},
        HomomorphicCommitmentScheme,
    };

    // Helper function to check if two elements are equal using constant-time comparison
    fn ct_eq<G: GroupElement>(a: &G, b: &G) -> bool {
        bool::from(a.ct_eq(b))
    }

    #[test]
    fn test_basic_commitment_correctness() {
        // Generate default public parameters for secp256k1
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        // Sample a message and randomness
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let message = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let randomness = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        // Create the commitment scheme
        let commitment_scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        // Compute the commitment using the scheme
        let commitment = commitment_scheme.commit(&([message].into()), &randomness);

        // Manually calculate the expected commitment
        // c_expected = m * G + r * H
        let message_generator = secp256k1::GroupElement::new(
            public_parameters.message_generators[0],
            public_parameters.commitment_space_public_parameters(),
        )
        .unwrap();
        let randomness_generator = secp256k1::GroupElement::new(
            public_parameters.randomness_generator,
            public_parameters.commitment_space_public_parameters(),
        )
        .unwrap();

        let expected_commitment =
            (message * message_generator) + (randomness * randomness_generator);

        // Assert that the computed commitment matches the expected value
        assert!(
            ct_eq(&commitment, &expected_commitment),
            "Commitment does not match expected value"
        );
    }

    /// Test that committing to the same message with different randomness
    /// produces distinct commitments.
    #[test]
    fn test_different_randomness() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let message = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let randomness1 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let randomness2 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        let commitment_scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        let c1 = commitment_scheme.commit(&([message].into()), &randomness1);
        let c2 = commitment_scheme.commit(&([message].into()), &randomness2);

        assert!(
            !ct_eq(&c1, &c2),
            "Commitments with different randomness should differ"
        );
    }

    /// Test homomorphism: commit(m1, r1) + commit(m2, r2) == commit(m1+m2, r1+r2).
    #[test]
    fn test_homomorphism() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let m1 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let r1 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let m2 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let r2 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        let scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        let c1 = scheme.commit(&([m1].into()), &r1);
        let c2 = scheme.commit(&([m2].into()), &r2);
        let left_sum = c1 + c2;

        let c12 = scheme.commit(&([(m1 + m2)].into()), &(r1 + r2));

        assert!(
            ct_eq(&left_sum, &c12),
            "Pedersen homomorphism property failed"
        );
    }

    /// Zero message: commit(0, r) == r*H
    #[test]
    fn test_zero_message() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let zero_message = secp256k1::Scalar::from(U256::ZERO);
        let r = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        let scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        let commitment = scheme.commit(&([zero_message].into()), &r);

        // Expected: commit(0, r) = r*H
        let h = secp256k1::GroupElement::new(
            public_parameters.randomness_generator,
            public_parameters.commitment_space_public_parameters(),
        )
        .unwrap();
        let expected = r * h;

        assert!(ct_eq(&commitment, &expected), "Zero message check failed");
    }

    /// Zero randomness: commit(m, 0) == m*G
    #[test]
    fn test_zero_randomness() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let message = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let zero_randomness = secp256k1::Scalar::from(U256::ZERO);

        let scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        let commitment = scheme.commit(&([message].into()), &zero_randomness);
        // Expected: m * G
        let g = secp256k1::GroupElement::new(
            public_parameters.message_generators[0],
            public_parameters.commitment_space_public_parameters(),
        )
        .unwrap();
        let expected = message * g;

        assert!(
            ct_eq(&commitment, &expected),
            "Zero randomness check failed"
        );
    }

    /// Internally Inconsistent Groups: pass BATCH_SIZE=0
    /// and expect `Error::InvalidPublicParameters`.
    #[test]
    fn test_internally_inconsistent_groups() {
        // Create a public parameters object with BATCH_SIZE=0 (should fail).
        let invalid_pedersen_params = pedersen::PublicParameters::<
            0,
            <secp256k1::GroupElement as GroupElement>::Value,
            <secp256k1::Scalar as GroupElement>::PublicParameters,
            <secp256k1::GroupElement as GroupElement>::PublicParameters,
        > {
            groups_public_parameters: commitment::GroupsPublicParameters {
                message_space_public_parameters: group::self_product::PublicParameters::new(
                    secp256k1::scalar::PublicParameters::default(),
                ),
                randomness_space_public_parameters: secp256k1::scalar::PublicParameters::default(),
                commitment_space_public_parameters:
                    secp256k1::group_element::PublicParameters::default(),
            },
            message_generators: [],
            randomness_generator: secp256k1::GroupElement::generator_from_public_parameters(
                &secp256k1::group_element::PublicParameters::default(),
            )
            .unwrap()
            .value(),
        };

        // Try creating the scheme with invalid parameters
        let err = Pedersen::<
            0,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&invalid_pedersen_params)
        .expect_err("Should fail on BATCH_SIZE=0");
        match err {
            commitment::Error::InvalidPublicParameters => (),
            _ => panic!("Expected InvalidPublicParameters error"),
        } // this passes so no issue here
    }

    /// Fuzz the message/randomness input. This is just a base for fuzzing if we need.
    #[test]
    fn test_fuzz_message_randomness() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        // Just do 50 random samples for demonstration.
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        for _ in 0..500 {
            let m = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
            let r = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
            // If there's a serious bug (like integer overflow), we'd likely panic or produce nonsense.
            let _ = scheme.commit(&([m].into()), &r);
        }
    }

    /// Collision checks: Attempt random commits, store them, and confirm no collisions
    /// for different (m, r). This is just a base for fuzzing if we need.
    #[test]
    fn test_collision_checks() {
        let public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&public_parameters)
        .unwrap();

        let scalar_pp = secp256k1::scalar::PublicParameters::default();
        let mut commitments = Vec::new();

        // We'll do 100 random commits
        for _ in 0..100 {
            let m = secp256k1::Scalar::sample(&scalar_pp, &mut OsRng).unwrap();
            let r = secp256k1::Scalar::sample(&scalar_pp, &mut OsRng).unwrap();
            let c = scheme.commit(&([m].into()), &r);

            // Check if this commitment equals any previous one
            assert!(
                !commitments.iter().any(|prev_c| ct_eq(prev_c, &c)),
                "Unexpected collision for randomly sampled (m,r)"
            );
            commitments.push(c);
        }
    }

    /// Distinct Generators: If H == G or if H is in the span of G, it breaks security.
    /// This test tries intentionally to pick the same generator for G and H, expecting
    /// the library or usage to fail or produce an error. The tests will pass if the scheme
    /// accepts the same generator for G and H, which is a security issue.
    #[test]
    fn test_distinct_generators() {
        // @audit-issue this passes so we add it to the report as low / info
        let scalar_pp = secp256k1::scalar::PublicParameters::default();
        let group_pp = secp256k1::group_element::PublicParameters::default();

        // Force the same generator for G and H
        let same_value = secp256k1::GroupElement::generator_from_public_parameters(&group_pp)
            .unwrap()
            .value();

        // BATCH_SIZE=1 to keep it simple
        let forced_pedersen_params =
            pedersen::PublicParameters::<
                1,
                <secp256k1::GroupElement as GroupElement>::Value,
                <secp256k1::Scalar as GroupElement>::PublicParameters,
                <secp256k1::GroupElement as GroupElement>::PublicParameters,
            >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>(
                scalar_pp,
                group_pp.clone(),
                [same_value], // G array
                same_value,   // H is the same as G
            );

        // We expect (under a secure library) that using the same generator might not fail
        // immediately at creation, but it definitely breaks the scheme's binding property.
        // A real test might do a collision or raise a security alarm. For demonstration,
        // we can attempt to see if scheme creation fails or at least produce a comment:
        let scheme_creation = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&forced_pedersen_params);

        // In some libraries, no direct error is thrown, but we do log or test collision:
        let scheme = scheme_creation.expect("Scheme creation didn't fail, but is insecure!");
        // We do a quick message test and see if collisions appear easily:
        let m1 = secp256k1::Scalar::from(U256::from(10u64));
        let r1 = secp256k1::Scalar::from(U256::from(0u64));
        let c1 = scheme.commit(&([m1].into()), &r1);

        let m2 = secp256k1::Scalar::from(U256::from(0u64));
        let r2 = secp256k1::Scalar::from(U256::from(10u64));
        let c2 = scheme.commit(&([m2].into()), &r2);

        // If G == H, c1 == c2 => 10*G + 0*H == 0*G + 10*H
        // This obviously reveals the binding break. We expect c1 == c2.
        assert!(
            ct_eq(&c1, &c2),
            "Generators are same, but no collision found?!"
        );
    }

    /// Scalability: tests a large batch size
    #[test]
    fn test_scalability() {
        const BATCH_SIZE: usize = 869; // @audit-issue the test fails at batch size of 869

        // Derive Pedersen for BATCH_SIZE
        // We do so by building a custom parameter structure with BATCH_SIZE=64:
        let scalar_pp = secp256k1::scalar::PublicParameters::default();
        let group_pp = secp256k1::group_element::PublicParameters::default();

        // We'll reuse the standard derivation for the single generator, repeating it 64 times:
        let default_params_1 = secp256k1::GroupElement::generator_from_public_parameters(&group_pp)
            .unwrap()
            .value();

        // Hash a random generator for H:
        let default_params_h = secp256k1::GroupElement::hash_to_group(
            b"commitment/pedersen: randomness generator scaling test",
        )
        .unwrap()
        .value();

        let message_generators = [default_params_1; BATCH_SIZE];
        let randomness_generator = default_params_h;

        // We can define the big pedersen parameters:
        let big_params =
            pedersen::PublicParameters::<
                BATCH_SIZE,
                <secp256k1::GroupElement as GroupElement>::Value,
                <secp256k1::Scalar as GroupElement>::PublicParameters,
                <secp256k1::GroupElement as GroupElement>::PublicParameters,
            >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>(
                scalar_pp,
                group_pp,
                message_generators,
                randomness_generator,
            );

        let scheme = Pedersen::<
            BATCH_SIZE,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&big_params)
        .unwrap();

        // Now commit to a 1024-dimensional message:
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let msgs = (0..BATCH_SIZE)
            .map(|_| secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap())
            .collect::<Vec<_>>();
        let r = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        // Convert Vec to array first, then into GroupElement
        let msgs_array: [secp256k1::Scalar; BATCH_SIZE] = msgs.try_into().unwrap();
        let batched_message = msgs_array.into();
        let commitment = scheme.commit(&batched_message, &r);

        // For a real scalability test, you might measure timing or memory usage here:
        assert!(
            !ct_eq(&commitment, &commitment.neutral()),
            "Commitment unexpectedly equals identity in large-batch test"
        );
    }

    /// Test that identity point is rejected as a generator
    #[test]
    fn test_identity_point_rejection() {
        let scalar_pp = secp256k1::scalar::PublicParameters::default();
        let group_pp = secp256k1::group_element::PublicParameters::default();

        // Get the identity element
        let identity = secp256k1::GroupElement::neutral_from_public_parameters(&group_pp).unwrap();
        let identity_value = identity.value();

        // Try to create parameters with identity as message generator
        let invalid_g_params =
            pedersen::PublicParameters::<
                1,
                <secp256k1::GroupElement as GroupElement>::Value,
                <secp256k1::Scalar as GroupElement>::PublicParameters,
                <secp256k1::GroupElement as GroupElement>::PublicParameters,
            >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>(
                scalar_pp.clone(),
                group_pp.clone(),
                [identity_value], // G is identity
                secp256k1::GroupElement::hash_to_group(b"randomness generator")
                    .unwrap()
                    .value(),
            );

        // Try creating the scheme with identity as G
        let result_g = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&invalid_g_params);

        // Try to create parameters with identity as randomness generator
        let invalid_h_params =
            pedersen::PublicParameters::<
                1,
                <secp256k1::GroupElement as GroupElement>::Value,
                <secp256k1::Scalar as GroupElement>::PublicParameters,
                <secp256k1::GroupElement as GroupElement>::PublicParameters,
            >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>(
                scalar_pp,
                group_pp,
                [secp256k1::GroupElement::generator_from_public_parameters(
                    &secp256k1::group_element::PublicParameters::default(),
                )
                .unwrap()
                .value()],
                identity_value, // H is identity
            );

        // Try creating the scheme with identity as H
        let result_h = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&invalid_h_params);

        // Check both results and log which ones fail
        let g_rejects_identity = result_g.is_err();
        let h_rejects_identity = result_h.is_err();

        println!(
            "Identity point rejection test results:\n\
             - G rejects identity: {}\n\
             - H rejects identity: {}",
            g_rejects_identity, h_rejects_identity
        );

        // Combined assertion to see if both checks pass
        assert!(
            // @audit-issue this fails so we add it to the report as low / info
            g_rejects_identity && h_rejects_identity,
            "Scheme creation should fail when using identity element as generator. \
             G rejection: {}, H rejection: {}",
            g_rejects_identity,
            h_rejects_identity
        );
    }
}
