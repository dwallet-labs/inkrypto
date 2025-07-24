from sage.crypto.util import random_prime
from sage.all import *
from math import log2

def zero_pad(x, bits):
    s = hex(x).replace('0x', '')
    assert bits % 4 == 0
    assert bits >= 4*len(s)
    while 4*len(s) != bits:
        s = '0' + s
    return s


def generate_primes_and_crt(bit_length, crt_fund_bits, crt_non_fund_bits, crt_coefficient_bits, prime_mult_bits, encryption_of_secret_primes, secret_share_primes):
    """
    Generates a list of M random primes with the specified bit length
    and computes the CRT coefficients.
    Args:
        bit_length (int): Number of bits for each prime.
        max_primes (int): Number of max primes to generate.
        secret_share_share_primes (int): Number min primes to generate for secret share share encryptions.
        secret_share_primes (int): Number min primes to generate for secret share encryptions.
    Prints code for:
        - List of M random primes.
        - List of CRT coefficients for the M primes.
        - List of CRT coefficients for the M1 primes.
    """
    max_primes = secret_share_primes

    header = '''use crypto_bigint::{{U{PRIME_BITS}, U{FUND_BITS}, U{NON_FUND_BITS}}};
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{{CRTCoefficientSizedNumber, CRTPrimeSizedNumber, CRTReconstructionSizedNumber}};'''
    print(header.format(PRIME_BITS = bit_length, FUND_BITS = crt_fund_bits, NON_FUND_BITS = crt_non_fund_bits))
    print('pub const NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES: usize = ' + str(encryption_of_secret_primes) +';')
    print('pub const MAX_PRIMES: usize = ' + str(max_primes) +';')
    print('pub const CRT_PRIME_LIMBS: usize = U' + str(bit_length) +'::LIMBS;')
    print('pub const CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U' + str(crt_fund_bits) +'::LIMBS;')
    print('pub const CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U' + str(crt_non_fund_bits) +'::LIMBS;')

    # Generate M random primes of the specified bit length
    primes = [random_prime(2**bit_length - 1, lbound=2**(bit_length - 1)) for _ in range(max_primes)]

    # Compute the product of all primes
    product = prod(primes)
    print('pub const CRT_PRIMES_PRODUCT: CRTReconstructionSizedNumber = CRTReconstructionSizedNumber::from_be_hex("' + zero_pad(product, prime_mult_bits) + '");')

    # Compute MAX CRT coefficients
    crt_coefficients = []
    for p in primes:
        Mi = product // p  # Product of all other primes
        Mi_inverse = inverse_mod(Mi, p)  # Modular inverse of Mi mod p
        crt_coefficients.append(Mi * Mi_inverse)

    print('pub const CRT_PRIMES: [CRTPrimeSizedNumber; MAX_PRIMES] = [')
    for i in range(max_primes):
        print('CRTPrimeSizedNumber::from_be_hex("' + zero_pad(primes[i], bit_length) + '"),')
    print('];')

    print('pub const CRT_COEFFICIENTS: [CRTCoefficientSizedNumber; MAX_PRIMES] = [')
    for i in range(max_primes):
        print('CRTCoefficientSizedNumber::from_be_hex("' + zero_pad(crt_coefficients[i], crt_coefficient_bits) + '"),')
    print('];')

    # Compute the product of primes for encryption of secret
    product = prod(primes[0:encryption_of_secret_primes])
    print('pub const ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT: CRTReconstructionSizedNumber = CRTReconstructionSizedNumber::from_be_hex("' + zero_pad(product, prime_mult_bits) + '");')

    # Compute secret share CRT coefficients
    crt_coefficients = []
    for p in primes[0:encryption_of_secret_primes]:
        Mi = product // p  # Product of all other primes
        Mi_inverse = inverse_mod(Mi, p)  # Modular inverse of Mi mod p
        crt_coefficients.append(Mi * Mi_inverse)

    print('pub const ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS: [CRTCoefficientSizedNumber; NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] = [')
    for i in range(encryption_of_secret_primes):
        print('CRTCoefficientSizedNumber::from_be_hex("' + zero_pad(crt_coefficients[i], crt_coefficient_bits) + '"),')
    print('];')

header = '''
// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file was auto-generated via `scripts/generate_primes.py`.
//! Run from project root: 
//! `/usr/local/bin/sage scripts/generate_primes.py > class-groups/src/publicly_verifiable_secret_sharing/chinese_remainder_theorem/consts.rs`
'''
print(header)
generate_primes_and_crt(640, 1536, 3072, 2048, 3072, 2, 3)
# generate_primes_and_crt(768, 1536, 3072, 4096, 6144, 2, 3)
# generate_primes_and_crt(896, 1536, 4096, 4096, 6144, 1, 2)
print()
