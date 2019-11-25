; Copyright (c) 2018, Google Inc.
;
; Permission to use, copy, modify, and/or distribute this software for any
; purpose with or without fee is hereby granted, provided that the above
; copyright notice and this permission notice appear in all copies.
;
; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
; WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
; MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
; SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
; WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
; OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
; CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

; 32-bit Windows adds underscores to C functions, while 64-bit Windows does not.
%ifidn __OUTPUT_FORMAT__, win32
%xdefine __objectivepgp_AES_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_cbc_encrypt
%xdefine __objectivepgp_AES_cfb128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_cfb128_encrypt
%xdefine __objectivepgp_AES_ctr128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_ctr128_encrypt
%xdefine __objectivepgp_AES_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_decrypt
%xdefine __objectivepgp_AES_ecb_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_ecb_encrypt
%xdefine __objectivepgp_AES_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_encrypt
%xdefine __objectivepgp_AES_ofb128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_ofb128_encrypt
%xdefine __objectivepgp_AES_set_decrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_set_decrypt_key
%xdefine __objectivepgp_AES_set_encrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_set_encrypt_key
%xdefine __objectivepgp_AES_unwrap_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_unwrap_key
%xdefine __objectivepgp_AES_unwrap_key_padded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_unwrap_key_padded
%xdefine __objectivepgp_AES_wrap_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_wrap_key
%xdefine __objectivepgp_AES_wrap_key_padded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_wrap_key_padded
%xdefine __objectivepgp_BN_BLINDING_convert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_convert
%xdefine __objectivepgp_BN_BLINDING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_free
%xdefine __objectivepgp_BN_BLINDING_invert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_invert
%xdefine __objectivepgp_BN_BLINDING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_new
%xdefine __objectivepgp_BN_CTX_end _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_end
%xdefine __objectivepgp_BN_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_free
%xdefine __objectivepgp_BN_CTX_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_get
%xdefine __objectivepgp_BN_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_new
%xdefine __objectivepgp_BN_CTX_start _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_start
%xdefine __objectivepgp_BN_GENCB_call _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_GENCB_call
%xdefine __objectivepgp_BN_GENCB_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_GENCB_set
%xdefine __objectivepgp_BN_MONT_CTX_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_copy
%xdefine __objectivepgp_BN_MONT_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_free
%xdefine __objectivepgp_BN_MONT_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new
%xdefine __objectivepgp_BN_MONT_CTX_new_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new_consttime
%xdefine __objectivepgp_BN_MONT_CTX_new_for_modulus _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new_for_modulus
%xdefine __objectivepgp_BN_MONT_CTX_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_set
%xdefine __objectivepgp_BN_MONT_CTX_set_locked _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_set_locked
%xdefine __objectivepgp_BN_abs_is_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_abs_is_word
%xdefine __objectivepgp_BN_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_add
%xdefine __objectivepgp_BN_add_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_add_word
%xdefine __objectivepgp_BN_bin2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bin2bn
%xdefine __objectivepgp_BN_bn2bin _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2bin
%xdefine __objectivepgp_BN_bn2bin_padded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2bin_padded
%xdefine __objectivepgp_BN_bn2le_padded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2le_padded
%xdefine __objectivepgp_BN_clear _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_clear
%xdefine __objectivepgp_BN_clear_bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_clear_bit
%xdefine __objectivepgp_BN_clear_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_clear_free
%xdefine __objectivepgp_BN_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_cmp
%xdefine __objectivepgp_BN_cmp_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_cmp_word
%xdefine __objectivepgp_BN_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_copy
%xdefine __objectivepgp_BN_count_low_zero_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_count_low_zero_bits
%xdefine __objectivepgp_BN_div _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_div
%xdefine __objectivepgp_BN_div_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_div_word
%xdefine __objectivepgp_BN_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_dup
%xdefine __objectivepgp_BN_enhanced_miller_rabin_primality_test _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_enhanced_miller_rabin_primality_test
%xdefine __objectivepgp_BN_equal_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_equal_consttime
%xdefine __objectivepgp_BN_exp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_exp
%xdefine __objectivepgp_BN_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_free
%xdefine __objectivepgp_BN_from_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_from_montgomery
%xdefine __objectivepgp_BN_gcd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_gcd
%xdefine __objectivepgp_BN_generate_prime_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_generate_prime_ex
%xdefine __objectivepgp_BN_get_u64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_get_u64
%xdefine __objectivepgp_BN_get_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_get_word
%xdefine __objectivepgp_BN_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_init
%xdefine __objectivepgp_BN_is_bit_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_bit_set
%xdefine __objectivepgp_BN_is_negative _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_negative
%xdefine __objectivepgp_BN_is_odd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_odd
%xdefine __objectivepgp_BN_is_one _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_one
%xdefine __objectivepgp_BN_is_pow2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_pow2
%xdefine __objectivepgp_BN_is_prime_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_prime_ex
%xdefine __objectivepgp_BN_is_prime_fasttest_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_prime_fasttest_ex
%xdefine __objectivepgp_BN_is_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_word
%xdefine __objectivepgp_BN_is_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_is_zero
%xdefine __objectivepgp_BN_le2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_le2bn
%xdefine __objectivepgp_BN_lshift _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_lshift
%xdefine __objectivepgp_BN_lshift1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_lshift1
%xdefine __objectivepgp_BN_mask_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mask_bits
%xdefine __objectivepgp_BN_mod_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_add
%xdefine __objectivepgp_BN_mod_add_quick _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_add_quick
%xdefine __objectivepgp_BN_mod_exp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp
%xdefine __objectivepgp_BN_mod_exp2_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp2_mont
%xdefine __objectivepgp_BN_mod_exp_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont
%xdefine __objectivepgp_BN_mod_exp_mont_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont_consttime
%xdefine __objectivepgp_BN_mod_exp_mont_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont_word
%xdefine __objectivepgp_BN_mod_inverse _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse
%xdefine __objectivepgp_BN_mod_inverse_blinded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse_blinded
%xdefine __objectivepgp_BN_mod_inverse_odd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse_odd
%xdefine __objectivepgp_BN_mod_lshift _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift
%xdefine __objectivepgp_BN_mod_lshift1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift1
%xdefine __objectivepgp_BN_mod_lshift1_quick _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift1_quick
%xdefine __objectivepgp_BN_mod_lshift_quick _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift_quick
%xdefine __objectivepgp_BN_mod_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_mul
%xdefine __objectivepgp_BN_mod_mul_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_mul_montgomery
%xdefine __objectivepgp_BN_mod_pow2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_pow2
%xdefine __objectivepgp_BN_mod_sqr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sqr
%xdefine __objectivepgp_BN_mod_sqrt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sqrt
%xdefine __objectivepgp_BN_mod_sub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sub
%xdefine __objectivepgp_BN_mod_sub_quick _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sub_quick
%xdefine __objectivepgp_BN_mod_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_word
%xdefine __objectivepgp_BN_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mul
%xdefine __objectivepgp_BN_mul_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mul_word
%xdefine __objectivepgp_BN_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_new
%xdefine __objectivepgp_BN_nnmod _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_nnmod
%xdefine __objectivepgp_BN_nnmod_pow2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_nnmod_pow2
%xdefine __objectivepgp_BN_num_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bits
%xdefine __objectivepgp_BN_num_bits_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bits_word
%xdefine __objectivepgp_BN_num_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bytes
%xdefine __objectivepgp_BN_one _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_one
%xdefine __objectivepgp_BN_primality_test _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_primality_test
%xdefine __objectivepgp_BN_pseudo_rand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_pseudo_rand
%xdefine __objectivepgp_BN_pseudo_rand_range _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_pseudo_rand_range
%xdefine __objectivepgp_BN_rand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_rand
%xdefine __objectivepgp_BN_rand_range _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_rand_range
%xdefine __objectivepgp_BN_rand_range_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_rand_range_ex
%xdefine __objectivepgp_BN_rshift _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_rshift
%xdefine __objectivepgp_BN_rshift1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_rshift1
%xdefine __objectivepgp_BN_set_bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_set_bit
%xdefine __objectivepgp_BN_set_negative _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_set_negative
%xdefine __objectivepgp_BN_set_u64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_set_u64
%xdefine __objectivepgp_BN_set_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_set_word
%xdefine __objectivepgp_BN_sqr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_sqr
%xdefine __objectivepgp_BN_sqrt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_sqrt
%xdefine __objectivepgp_BN_sub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_sub
%xdefine __objectivepgp_BN_sub_word _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_sub_word
%xdefine __objectivepgp_BN_to_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_to_montgomery
%xdefine __objectivepgp_BN_uadd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_uadd
%xdefine __objectivepgp_BN_ucmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_ucmp
%xdefine __objectivepgp_BN_usub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_usub
%xdefine __objectivepgp_BN_value_one _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_value_one
%xdefine __objectivepgp_BN_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_zero
%xdefine __objectivepgp_BORINGSSL_self_test _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BORINGSSL_self_test
%xdefine __objectivepgp_CRYPTO_POLYVAL_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_finish
%xdefine __objectivepgp_CRYPTO_POLYVAL_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_init
%xdefine __objectivepgp_CRYPTO_POLYVAL_update_blocks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_update_blocks
%xdefine __objectivepgp_CRYPTO_cbc128_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cbc128_decrypt
%xdefine __objectivepgp_CRYPTO_cbc128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cbc128_encrypt
%xdefine __objectivepgp_CRYPTO_cfb128_1_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_1_encrypt
%xdefine __objectivepgp_CRYPTO_cfb128_8_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_8_encrypt
%xdefine __objectivepgp_CRYPTO_cfb128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_encrypt
%xdefine __objectivepgp_CRYPTO_ctr128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ctr128_encrypt
%xdefine __objectivepgp_CRYPTO_ctr128_encrypt_ctr32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ctr128_encrypt_ctr32
%xdefine __objectivepgp_CRYPTO_gcm128_aad _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_aad
%xdefine __objectivepgp_CRYPTO_gcm128_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_decrypt
%xdefine __objectivepgp_CRYPTO_gcm128_decrypt_ctr32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_decrypt_ctr32
%xdefine __objectivepgp_CRYPTO_gcm128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_encrypt
%xdefine __objectivepgp_CRYPTO_gcm128_encrypt_ctr32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_encrypt_ctr32
%xdefine __objectivepgp_CRYPTO_gcm128_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_finish
%xdefine __objectivepgp_CRYPTO_gcm128_init_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_init_key
%xdefine __objectivepgp_CRYPTO_gcm128_setiv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_setiv
%xdefine __objectivepgp_CRYPTO_gcm128_tag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_tag
%xdefine __objectivepgp_CRYPTO_ghash_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ghash_init
%xdefine __objectivepgp_CRYPTO_ofb128_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ofb128_encrypt
%xdefine __objectivepgp_CRYPTO_sysrand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_sysrand
%xdefine __objectivepgp_CRYPTO_tls1_prf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_tls1_prf
%xdefine __objectivepgp_CTR_DRBG_clear _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_clear
%xdefine __objectivepgp_CTR_DRBG_generate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_generate
%xdefine __objectivepgp_CTR_DRBG_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_init
%xdefine __objectivepgp_CTR_DRBG_reseed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_reseed
%xdefine __objectivepgp_DES_decrypt3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_decrypt3
%xdefine __objectivepgp_DES_ecb3_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_ecb3_encrypt
%xdefine __objectivepgp_DES_ecb_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_ecb_encrypt
%xdefine __objectivepgp_DES_ede2_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_ede2_cbc_encrypt
%xdefine __objectivepgp_DES_ede3_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_ede3_cbc_encrypt
%xdefine __objectivepgp_DES_encrypt3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_encrypt3
%xdefine __objectivepgp_DES_ncbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_ncbc_encrypt
%xdefine __objectivepgp_DES_set_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_set_key
%xdefine __objectivepgp_DES_set_key_unchecked _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_set_key_unchecked
%xdefine __objectivepgp_DES_set_odd_parity _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DES_set_odd_parity
%xdefine __objectivepgp_ECDH_compute_key_fips _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDH_compute_key_fips
%xdefine __objectivepgp_ECDSA_SIG_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_free
%xdefine __objectivepgp_ECDSA_SIG_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_get0
%xdefine __objectivepgp_ECDSA_SIG_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_new
%xdefine __objectivepgp_ECDSA_SIG_set0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_set0
%xdefine __objectivepgp_ECDSA_do_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_do_sign
%xdefine __objectivepgp_ECDSA_do_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_do_verify
%xdefine __objectivepgp_EC_GFp_mont_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_mont_method
%xdefine __objectivepgp_EC_GFp_nistp224_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistp224_method
%xdefine __objectivepgp_EC_GFp_nistp256_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistp256_method
%xdefine __objectivepgp_EC_GFp_nistz256_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistz256_method
%xdefine __objectivepgp_EC_GROUP_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_cmp
%xdefine __objectivepgp_EC_GROUP_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_dup
%xdefine __objectivepgp_EC_GROUP_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_free
%xdefine __objectivepgp_EC_GROUP_get0_generator _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get0_generator
%xdefine __objectivepgp_EC_GROUP_get0_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get0_order
%xdefine __objectivepgp_EC_GROUP_get_cofactor _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_cofactor
%xdefine __objectivepgp_EC_GROUP_get_curve_GFp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_curve_GFp
%xdefine __objectivepgp_EC_GROUP_get_curve_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_curve_name
%xdefine __objectivepgp_EC_GROUP_get_degree _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_degree
%xdefine __objectivepgp_EC_GROUP_get_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_order
%xdefine __objectivepgp_EC_GROUP_method_of _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_method_of
%xdefine __objectivepgp_EC_GROUP_new_by_curve_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_new_by_curve_name
%xdefine __objectivepgp_EC_GROUP_new_curve_GFp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_new_curve_GFp
%xdefine __objectivepgp_EC_GROUP_order_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_order_bits
%xdefine __objectivepgp_EC_GROUP_set_asn1_flag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_asn1_flag
%xdefine __objectivepgp_EC_GROUP_set_generator _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_generator
%xdefine __objectivepgp_EC_GROUP_set_point_conversion_form _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_point_conversion_form
%xdefine __objectivepgp_EC_KEY_check_fips _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_check_fips
%xdefine __objectivepgp_EC_KEY_check_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_check_key
%xdefine __objectivepgp_EC_KEY_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_dup
%xdefine __objectivepgp_EC_KEY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_free
%xdefine __objectivepgp_EC_KEY_generate_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_generate_key
%xdefine __objectivepgp_EC_KEY_generate_key_fips _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_generate_key_fips
%xdefine __objectivepgp_EC_KEY_get0_group _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_group
%xdefine __objectivepgp_EC_KEY_get0_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_private_key
%xdefine __objectivepgp_EC_KEY_get0_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_public_key
%xdefine __objectivepgp_EC_KEY_get_conv_form _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_conv_form
%xdefine __objectivepgp_EC_KEY_get_enc_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_enc_flags
%xdefine __objectivepgp_EC_KEY_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_ex_data
%xdefine __objectivepgp_EC_KEY_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_ex_new_index
%xdefine __objectivepgp_EC_KEY_is_opaque _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_is_opaque
%xdefine __objectivepgp_EC_KEY_key2buf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_key2buf
%xdefine __objectivepgp_EC_KEY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new
%xdefine __objectivepgp_EC_KEY_new_by_curve_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new_by_curve_name
%xdefine __objectivepgp_EC_KEY_new_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new_method
%xdefine __objectivepgp_EC_KEY_set_asn1_flag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_asn1_flag
%xdefine __objectivepgp_EC_KEY_set_conv_form _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_conv_form
%xdefine __objectivepgp_EC_KEY_set_enc_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_enc_flags
%xdefine __objectivepgp_EC_KEY_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_ex_data
%xdefine __objectivepgp_EC_KEY_set_group _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_group
%xdefine __objectivepgp_EC_KEY_set_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_private_key
%xdefine __objectivepgp_EC_KEY_set_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_public_key
%xdefine __objectivepgp_EC_KEY_set_public_key_affine_coordinates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_public_key_affine_coordinates
%xdefine __objectivepgp_EC_KEY_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_up_ref
%xdefine __objectivepgp_EC_METHOD_get_field_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_METHOD_get_field_type
%xdefine __objectivepgp_EC_POINT_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_add
%xdefine __objectivepgp_EC_POINT_clear_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_clear_free
%xdefine __objectivepgp_EC_POINT_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_cmp
%xdefine __objectivepgp_EC_POINT_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_copy
%xdefine __objectivepgp_EC_POINT_dbl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_dbl
%xdefine __objectivepgp_EC_POINT_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_dup
%xdefine __objectivepgp_EC_POINT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_free
%xdefine __objectivepgp_EC_POINT_get_affine_coordinates_GFp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_get_affine_coordinates_GFp
%xdefine __objectivepgp_EC_POINT_invert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_invert
%xdefine __objectivepgp_EC_POINT_is_at_infinity _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_is_at_infinity
%xdefine __objectivepgp_EC_POINT_is_on_curve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_is_on_curve
%xdefine __objectivepgp_EC_POINT_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_mul
%xdefine __objectivepgp_EC_POINT_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_new
%xdefine __objectivepgp_EC_POINT_oct2point _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_oct2point
%xdefine __objectivepgp_EC_POINT_point2oct _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_point2oct
%xdefine __objectivepgp_EC_POINT_set_affine_coordinates_GFp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_affine_coordinates_GFp
%xdefine __objectivepgp_EC_POINT_set_compressed_coordinates_GFp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_compressed_coordinates_GFp
%xdefine __objectivepgp_EC_POINT_set_to_infinity _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_to_infinity
%xdefine __objectivepgp_EC_curve_nid2nist _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_curve_nid2nist
%xdefine __objectivepgp_EC_curve_nist2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_curve_nist2nid
%xdefine __objectivepgp_EC_get_builtin_curves _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_get_builtin_curves
%xdefine __objectivepgp_EVP_AEAD_CTX_aead _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_aead
%xdefine __objectivepgp_EVP_AEAD_CTX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_cleanup
%xdefine __objectivepgp_EVP_AEAD_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_free
%xdefine __objectivepgp_EVP_AEAD_CTX_get_iv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_get_iv
%xdefine __objectivepgp_EVP_AEAD_CTX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_init
%xdefine __objectivepgp_EVP_AEAD_CTX_init_with_direction _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_init_with_direction
%xdefine __objectivepgp_EVP_AEAD_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_new
%xdefine __objectivepgp_EVP_AEAD_CTX_open _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_open
%xdefine __objectivepgp_EVP_AEAD_CTX_open_gather _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_open_gather
%xdefine __objectivepgp_EVP_AEAD_CTX_seal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_seal
%xdefine __objectivepgp_EVP_AEAD_CTX_seal_scatter _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_seal_scatter
%xdefine __objectivepgp_EVP_AEAD_CTX_tag_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_tag_len
%xdefine __objectivepgp_EVP_AEAD_CTX_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_zero
%xdefine __objectivepgp_EVP_AEAD_key_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_key_length
%xdefine __objectivepgp_EVP_AEAD_max_overhead _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_max_overhead
%xdefine __objectivepgp_EVP_AEAD_max_tag_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_max_tag_len
%xdefine __objectivepgp_EVP_AEAD_nonce_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_nonce_length
%xdefine __objectivepgp_EVP_CIPHER_CTX_block_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_block_size
%xdefine __objectivepgp_EVP_CIPHER_CTX_cipher _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_cipher
%xdefine __objectivepgp_EVP_CIPHER_CTX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_cleanup
%xdefine __objectivepgp_EVP_CIPHER_CTX_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_copy
%xdefine __objectivepgp_EVP_CIPHER_CTX_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_ctrl
%xdefine __objectivepgp_EVP_CIPHER_CTX_encrypting _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_encrypting
%xdefine __objectivepgp_EVP_CIPHER_CTX_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_flags
%xdefine __objectivepgp_EVP_CIPHER_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_free
%xdefine __objectivepgp_EVP_CIPHER_CTX_get_app_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_get_app_data
%xdefine __objectivepgp_EVP_CIPHER_CTX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_init
%xdefine __objectivepgp_EVP_CIPHER_CTX_iv_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_iv_length
%xdefine __objectivepgp_EVP_CIPHER_CTX_key_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_key_length
%xdefine __objectivepgp_EVP_CIPHER_CTX_mode _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_mode
%xdefine __objectivepgp_EVP_CIPHER_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_new
%xdefine __objectivepgp_EVP_CIPHER_CTX_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_nid
%xdefine __objectivepgp_EVP_CIPHER_CTX_reset _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_reset
%xdefine __objectivepgp_EVP_CIPHER_CTX_set_app_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_app_data
%xdefine __objectivepgp_EVP_CIPHER_CTX_set_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_flags
%xdefine __objectivepgp_EVP_CIPHER_CTX_set_key_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_key_length
%xdefine __objectivepgp_EVP_CIPHER_CTX_set_padding _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_padding
%xdefine __objectivepgp_EVP_CIPHER_block_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_block_size
%xdefine __objectivepgp_EVP_CIPHER_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_flags
%xdefine __objectivepgp_EVP_CIPHER_iv_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_iv_length
%xdefine __objectivepgp_EVP_CIPHER_key_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_key_length
%xdefine __objectivepgp_EVP_CIPHER_mode _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_mode
%xdefine __objectivepgp_EVP_CIPHER_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_nid
%xdefine __objectivepgp_EVP_Cipher _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_Cipher
%xdefine __objectivepgp_EVP_CipherFinal_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherFinal_ex
%xdefine __objectivepgp_EVP_CipherInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherInit
%xdefine __objectivepgp_EVP_CipherInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherInit_ex
%xdefine __objectivepgp_EVP_CipherUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherUpdate
%xdefine __objectivepgp_EVP_DecryptFinal_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptFinal_ex
%xdefine __objectivepgp_EVP_DecryptInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptInit
%xdefine __objectivepgp_EVP_DecryptInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptInit_ex
%xdefine __objectivepgp_EVP_DecryptUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptUpdate
%xdefine __objectivepgp_EVP_Digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_Digest
%xdefine __objectivepgp_EVP_DigestFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinal
%xdefine __objectivepgp_EVP_DigestFinalXOF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinalXOF
%xdefine __objectivepgp_EVP_DigestFinal_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinal_ex
%xdefine __objectivepgp_EVP_DigestInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestInit
%xdefine __objectivepgp_EVP_DigestInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestInit_ex
%xdefine __objectivepgp_EVP_DigestUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestUpdate
%xdefine __objectivepgp_EVP_EncryptFinal_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptFinal_ex
%xdefine __objectivepgp_EVP_EncryptInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptInit
%xdefine __objectivepgp_EVP_EncryptInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptInit_ex
%xdefine __objectivepgp_EVP_EncryptUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptUpdate
%xdefine __objectivepgp_EVP_MD_CTX_block_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_block_size
%xdefine __objectivepgp_EVP_MD_CTX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_cleanup
%xdefine __objectivepgp_EVP_MD_CTX_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_copy
%xdefine __objectivepgp_EVP_MD_CTX_copy_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_copy_ex
%xdefine __objectivepgp_EVP_MD_CTX_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_create
%xdefine __objectivepgp_EVP_MD_CTX_destroy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_destroy
%xdefine __objectivepgp_EVP_MD_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_free
%xdefine __objectivepgp_EVP_MD_CTX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_init
%xdefine __objectivepgp_EVP_MD_CTX_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_md
%xdefine __objectivepgp_EVP_MD_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_new
%xdefine __objectivepgp_EVP_MD_CTX_reset _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_reset
%xdefine __objectivepgp_EVP_MD_CTX_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_size
%xdefine __objectivepgp_EVP_MD_CTX_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_type
%xdefine __objectivepgp_EVP_MD_block_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_block_size
%xdefine __objectivepgp_EVP_MD_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_flags
%xdefine __objectivepgp_EVP_MD_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_size
%xdefine __objectivepgp_EVP_MD_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_type
%xdefine __objectivepgp_EVP_add_cipher_alias _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_add_cipher_alias
%xdefine __objectivepgp_EVP_add_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_add_digest
%xdefine __objectivepgp_EVP_aead_aes_128_gcm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm
%xdefine __objectivepgp_EVP_aead_aes_128_gcm_tls12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_tls12
%xdefine __objectivepgp_EVP_aead_aes_128_gcm_tls13 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_tls13
%xdefine __objectivepgp_EVP_aead_aes_256_gcm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm
%xdefine __objectivepgp_EVP_aead_aes_256_gcm_tls12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_tls12
%xdefine __objectivepgp_EVP_aead_aes_256_gcm_tls13 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_tls13
%xdefine __objectivepgp_EVP_aes_128_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_cbc
%xdefine __objectivepgp_EVP_aes_128_ctr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ctr
%xdefine __objectivepgp_EVP_aes_128_ecb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ecb
%xdefine __objectivepgp_EVP_aes_128_gcm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_gcm
%xdefine __objectivepgp_EVP_aes_128_ofb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ofb
%xdefine __objectivepgp_EVP_aes_192_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_cbc
%xdefine __objectivepgp_EVP_aes_192_ctr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ctr
%xdefine __objectivepgp_EVP_aes_192_ecb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ecb
%xdefine __objectivepgp_EVP_aes_192_gcm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_gcm
%xdefine __objectivepgp_EVP_aes_192_ofb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ofb
%xdefine __objectivepgp_EVP_aes_256_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_cbc
%xdefine __objectivepgp_EVP_aes_256_ctr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ctr
%xdefine __objectivepgp_EVP_aes_256_ecb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ecb
%xdefine __objectivepgp_EVP_aes_256_gcm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_gcm
%xdefine __objectivepgp_EVP_aes_256_ofb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ofb
%xdefine __objectivepgp_EVP_des_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_cbc
%xdefine __objectivepgp_EVP_des_ecb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ecb
%xdefine __objectivepgp_EVP_des_ede _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede
%xdefine __objectivepgp_EVP_des_ede3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3
%xdefine __objectivepgp_EVP_des_ede3_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3_cbc
%xdefine __objectivepgp_EVP_des_ede3_ecb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3_ecb
%xdefine __objectivepgp_EVP_des_ede_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede_cbc
%xdefine __objectivepgp_EVP_has_aes_hardware _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_has_aes_hardware
%xdefine __objectivepgp_EVP_md4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_md4
%xdefine __objectivepgp_EVP_md5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_md5
%xdefine __objectivepgp_EVP_md5_sha1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_md5_sha1
%xdefine __objectivepgp_EVP_sha1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha1
%xdefine __objectivepgp_EVP_sha224 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha224
%xdefine __objectivepgp_EVP_sha256 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha256
%xdefine __objectivepgp_EVP_sha384 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha384
%xdefine __objectivepgp_EVP_sha512 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha512
%xdefine __objectivepgp_HMAC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC
%xdefine __objectivepgp_HMAC_CTX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_cleanup
%xdefine __objectivepgp_HMAC_CTX_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_copy
%xdefine __objectivepgp_HMAC_CTX_copy_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_copy_ex
%xdefine __objectivepgp_HMAC_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_free
%xdefine __objectivepgp_HMAC_CTX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_init
%xdefine __objectivepgp_HMAC_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_new
%xdefine __objectivepgp_HMAC_CTX_reset _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_reset
%xdefine __objectivepgp_HMAC_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Final
%xdefine __objectivepgp_HMAC_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Init
%xdefine __objectivepgp_HMAC_Init_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Init_ex
%xdefine __objectivepgp_HMAC_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Update
%xdefine __objectivepgp_HMAC_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HMAC_size
%xdefine __objectivepgp_MD4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD4
%xdefine __objectivepgp_MD4_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD4_Final
%xdefine __objectivepgp_MD4_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD4_Init
%xdefine __objectivepgp_MD4_Transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD4_Transform
%xdefine __objectivepgp_MD4_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD4_Update
%xdefine __objectivepgp_MD5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD5
%xdefine __objectivepgp_MD5_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD5_Final
%xdefine __objectivepgp_MD5_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD5_Init
%xdefine __objectivepgp_MD5_Transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD5_Transform
%xdefine __objectivepgp_MD5_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_MD5_Update
%xdefine __objectivepgp_OPENSSL_built_in_curves _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_built_in_curves
%xdefine __objectivepgp_RAND_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_bytes
%xdefine __objectivepgp_RAND_bytes_with_additional_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_bytes_with_additional_data
%xdefine __objectivepgp_RAND_pseudo_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_pseudo_bytes
%xdefine __objectivepgp_RAND_set_urandom_fd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_set_urandom_fd
%xdefine __objectivepgp_RSAZ_1024_mod_exp_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSAZ_1024_mod_exp_avx2
%xdefine __objectivepgp_RSA_add_pkcs1_prefix _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_add_pkcs1_prefix
%xdefine __objectivepgp_RSA_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_bits
%xdefine __objectivepgp_RSA_blinding_on _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_blinding_on
%xdefine __objectivepgp_RSA_check_fips _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_check_fips
%xdefine __objectivepgp_RSA_check_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_check_key
%xdefine __objectivepgp_RSA_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_decrypt
%xdefine __objectivepgp_RSA_default_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_default_method
%xdefine __objectivepgp_RSA_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_encrypt
%xdefine __objectivepgp_RSA_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_flags
%xdefine __objectivepgp_RSA_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_free
%xdefine __objectivepgp_RSA_generate_key_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_generate_key_ex
%xdefine __objectivepgp_RSA_generate_key_fips _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_generate_key_fips
%xdefine __objectivepgp_RSA_get0_crt_params _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_crt_params
%xdefine __objectivepgp_RSA_get0_factors _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_factors
%xdefine __objectivepgp_RSA_get0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_key
%xdefine __objectivepgp_RSA_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_get_ex_data
%xdefine __objectivepgp_RSA_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_get_ex_new_index
%xdefine __objectivepgp_RSA_is_opaque _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_is_opaque
%xdefine __objectivepgp_RSA_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_new
%xdefine __objectivepgp_RSA_new_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_new_method
%xdefine __objectivepgp_RSA_padding_add_PKCS1_OAEP_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_OAEP_mgf1
%xdefine __objectivepgp_RSA_padding_add_PKCS1_PSS_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_PSS_mgf1
%xdefine __objectivepgp_RSA_padding_add_PKCS1_type_1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_type_1
%xdefine __objectivepgp_RSA_padding_add_PKCS1_type_2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_type_2
%xdefine __objectivepgp_RSA_padding_add_none _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_none
%xdefine __objectivepgp_RSA_padding_check_PKCS1_OAEP_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_OAEP_mgf1
%xdefine __objectivepgp_RSA_padding_check_PKCS1_type_1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_type_1
%xdefine __objectivepgp_RSA_padding_check_PKCS1_type_2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_type_2
%xdefine __objectivepgp_RSA_private_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_decrypt
%xdefine __objectivepgp_RSA_private_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_encrypt
%xdefine __objectivepgp_RSA_private_transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_transform
%xdefine __objectivepgp_RSA_public_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_decrypt
%xdefine __objectivepgp_RSA_public_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_encrypt
%xdefine __objectivepgp_RSA_set0_crt_params _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_crt_params
%xdefine __objectivepgp_RSA_set0_factors _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_factors
%xdefine __objectivepgp_RSA_set0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_key
%xdefine __objectivepgp_RSA_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_set_ex_data
%xdefine __objectivepgp_RSA_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign
%xdefine __objectivepgp_RSA_sign_pss_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign_pss_mgf1
%xdefine __objectivepgp_RSA_sign_raw _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign_raw
%xdefine __objectivepgp_RSA_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_size
%xdefine __objectivepgp_RSA_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_up_ref
%xdefine __objectivepgp_RSA_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify
%xdefine __objectivepgp_RSA_verify_PKCS1_PSS_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_PKCS1_PSS_mgf1
%xdefine __objectivepgp_RSA_verify_pss_mgf1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_pss_mgf1
%xdefine __objectivepgp_RSA_verify_raw _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_raw
%xdefine __objectivepgp_SHA1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA1
%xdefine __objectivepgp_SHA1_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Final
%xdefine __objectivepgp_SHA1_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Init
%xdefine __objectivepgp_SHA1_Transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Transform
%xdefine __objectivepgp_SHA1_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Update
%xdefine __objectivepgp_SHA224 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA224
%xdefine __objectivepgp_SHA224_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Final
%xdefine __objectivepgp_SHA224_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Init
%xdefine __objectivepgp_SHA224_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Update
%xdefine __objectivepgp_SHA256 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256
%xdefine __objectivepgp_SHA256_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Final
%xdefine __objectivepgp_SHA256_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Init
%xdefine __objectivepgp_SHA256_Transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Transform
%xdefine __objectivepgp_SHA256_TransformBlocks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256_TransformBlocks
%xdefine __objectivepgp_SHA256_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Update
%xdefine __objectivepgp_SHA384 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA384
%xdefine __objectivepgp_SHA384_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Final
%xdefine __objectivepgp_SHA384_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Init
%xdefine __objectivepgp_SHA384_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Update
%xdefine __objectivepgp_SHA512 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA512
%xdefine __objectivepgp_SHA512_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Final
%xdefine __objectivepgp_SHA512_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Init
%xdefine __objectivepgp_SHA512_Transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Transform
%xdefine __objectivepgp_SHA512_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Update
%xdefine __objectivepgp_aes_ctr_set_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_ctr_set_key
%xdefine __objectivepgp_bn_abs_sub_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_abs_sub_consttime
%xdefine __objectivepgp_bn_add_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_add_words
%xdefine __objectivepgp_bn_copy_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_copy_words
%xdefine __objectivepgp_bn_div_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_div_consttime
%xdefine __objectivepgp_bn_expand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_expand
%xdefine __objectivepgp_bn_fits_in_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_fits_in_words
%xdefine __objectivepgp_bn_from_montgomery_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_from_montgomery_small
%xdefine __objectivepgp_bn_in_range_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_in_range_words
%xdefine __objectivepgp_bn_is_bit_set_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_is_bit_set_words
%xdefine __objectivepgp_bn_is_relatively_prime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_is_relatively_prime
%xdefine __objectivepgp_bn_jacobi _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_jacobi
%xdefine __objectivepgp_bn_lcm_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_lcm_consttime
%xdefine __objectivepgp_bn_less_than_montgomery_R _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_less_than_montgomery_R
%xdefine __objectivepgp_bn_less_than_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_less_than_words
%xdefine __objectivepgp_bn_minimal_width _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_minimal_width
%xdefine __objectivepgp_bn_mod_add_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_add_consttime
%xdefine __objectivepgp_bn_mod_add_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_add_words
%xdefine __objectivepgp_bn_mod_exp_base_2_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_exp_base_2_consttime
%xdefine __objectivepgp_bn_mod_exp_mont_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_exp_mont_small
%xdefine __objectivepgp_bn_mod_inverse_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_consttime
%xdefine __objectivepgp_bn_mod_inverse_prime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_prime
%xdefine __objectivepgp_bn_mod_inverse_prime_mont_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_prime_mont_small
%xdefine __objectivepgp_bn_mod_inverse_secret_prime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_secret_prime
%xdefine __objectivepgp_bn_mod_lshift1_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_lshift1_consttime
%xdefine __objectivepgp_bn_mod_lshift_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_lshift_consttime
%xdefine __objectivepgp_bn_mod_mul_montgomery_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_mul_montgomery_small
%xdefine __objectivepgp_bn_mod_sub_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_sub_consttime
%xdefine __objectivepgp_bn_mod_sub_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_sub_words
%xdefine __objectivepgp_bn_mod_u16_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_u16_consttime
%xdefine __objectivepgp_bn_mont_n0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mont_n0
%xdefine __objectivepgp_bn_mul_add_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_add_words
%xdefine __objectivepgp_bn_mul_comba4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_comba4
%xdefine __objectivepgp_bn_mul_comba8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_comba8
%xdefine __objectivepgp_bn_mul_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_consttime
%xdefine __objectivepgp_bn_mul_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_small
%xdefine __objectivepgp_bn_mul_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_words
%xdefine __objectivepgp_bn_odd_number_is_obviously_composite _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_odd_number_is_obviously_composite
%xdefine __objectivepgp_bn_one_to_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_one_to_montgomery
%xdefine __objectivepgp_bn_rand_range_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_rand_range_words
%xdefine __objectivepgp_bn_rand_secret_range _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_rand_secret_range
%xdefine __objectivepgp_bn_reduce_once _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_reduce_once
%xdefine __objectivepgp_bn_reduce_once_in_place _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_reduce_once_in_place
%xdefine __objectivepgp_bn_resize_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_resize_words
%xdefine __objectivepgp_bn_rshift1_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift1_words
%xdefine __objectivepgp_bn_rshift_secret_shift _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift_secret_shift
%xdefine __objectivepgp_bn_rshift_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift_words
%xdefine __objectivepgp_bn_select_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_select_words
%xdefine __objectivepgp_bn_set_minimal_width _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_set_minimal_width
%xdefine __objectivepgp_bn_set_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_set_words
%xdefine __objectivepgp_bn_sqr_comba4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_comba4
%xdefine __objectivepgp_bn_sqr_comba8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_comba8
%xdefine __objectivepgp_bn_sqr_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_consttime
%xdefine __objectivepgp_bn_sqr_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_small
%xdefine __objectivepgp_bn_sqr_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_words
%xdefine __objectivepgp_bn_sub_words _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sub_words
%xdefine __objectivepgp_bn_to_montgomery_small _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_to_montgomery_small
%xdefine __objectivepgp_bn_uadd_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_uadd_consttime
%xdefine __objectivepgp_bn_usub_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_usub_consttime
%xdefine __objectivepgp_bn_wexpand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_wexpand
%xdefine __objectivepgp_crypto_gcm_clmul_enabled _ %+ BORINGSSL_PREFIX %+ __objectivepgp_crypto_gcm_clmul_enabled
%xdefine __objectivepgp_ec_GFp_mont_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_add
%xdefine __objectivepgp_ec_GFp_mont_bignum_to_felem _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_bignum_to_felem
%xdefine __objectivepgp_ec_GFp_mont_dbl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_dbl
%xdefine __objectivepgp_ec_GFp_mont_felem_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_mul
%xdefine __objectivepgp_ec_GFp_mont_felem_sqr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_sqr
%xdefine __objectivepgp_ec_GFp_mont_felem_to_bignum _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_to_bignum
%xdefine __objectivepgp_ec_GFp_mont_group_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_finish
%xdefine __objectivepgp_ec_GFp_mont_group_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_init
%xdefine __objectivepgp_ec_GFp_mont_group_set_curve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_set_curve
%xdefine __objectivepgp_ec_GFp_mont_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul
%xdefine __objectivepgp_ec_GFp_mont_mul_base _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul_base
%xdefine __objectivepgp_ec_GFp_mont_mul_public _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul_public
%xdefine __objectivepgp_ec_GFp_nistp_recode_scalar_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_nistp_recode_scalar_bits
%xdefine __objectivepgp_ec_GFp_simple_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_cmp
%xdefine __objectivepgp_ec_GFp_simple_cmp_x_coordinate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_cmp_x_coordinate
%xdefine __objectivepgp_ec_GFp_simple_group_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_finish
%xdefine __objectivepgp_ec_GFp_simple_group_get_curve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_get_curve
%xdefine __objectivepgp_ec_GFp_simple_group_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_init
%xdefine __objectivepgp_ec_GFp_simple_group_set_curve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_set_curve
%xdefine __objectivepgp_ec_GFp_simple_invert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_invert
%xdefine __objectivepgp_ec_GFp_simple_is_at_infinity _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_is_at_infinity
%xdefine __objectivepgp_ec_GFp_simple_is_on_curve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_is_on_curve
%xdefine __objectivepgp_ec_GFp_simple_mont_inv_mod_ord_vartime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_mont_inv_mod_ord_vartime
%xdefine __objectivepgp_ec_GFp_simple_point_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_copy
%xdefine __objectivepgp_ec_GFp_simple_point_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_init
%xdefine __objectivepgp_ec_GFp_simple_point_set_affine_coordinates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_set_affine_coordinates
%xdefine __objectivepgp_ec_GFp_simple_point_set_to_infinity _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_set_to_infinity
%xdefine __objectivepgp_ec_bignum_to_felem _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_bignum_to_felem
%xdefine __objectivepgp_ec_bignum_to_scalar _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_bignum_to_scalar
%xdefine __objectivepgp_ec_cmp_x_coordinate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_cmp_x_coordinate
%xdefine __objectivepgp_ec_compute_wNAF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_compute_wNAF
%xdefine __objectivepgp_ec_felem_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_add
%xdefine __objectivepgp_ec_felem_equal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_equal
%xdefine __objectivepgp_ec_felem_neg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_neg
%xdefine __objectivepgp_ec_felem_non_zero_mask _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_non_zero_mask
%xdefine __objectivepgp_ec_felem_select _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_select
%xdefine __objectivepgp_ec_felem_sub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_sub
%xdefine __objectivepgp_ec_felem_to_bignum _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_to_bignum
%xdefine __objectivepgp_ec_get_x_coordinate_as_scalar _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_get_x_coordinate_as_scalar
%xdefine __objectivepgp_ec_group_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_group_new
%xdefine __objectivepgp_ec_point_get_affine_coordinate_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_point_get_affine_coordinate_bytes
%xdefine __objectivepgp_ec_point_mul_scalar _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar
%xdefine __objectivepgp_ec_point_mul_scalar_base _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar_base
%xdefine __objectivepgp_ec_point_mul_scalar_public _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar_public
%xdefine __objectivepgp_ec_random_nonzero_scalar _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_random_nonzero_scalar
%xdefine __objectivepgp_ec_scalar_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_add
%xdefine __objectivepgp_ec_scalar_equal_vartime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_equal_vartime
%xdefine __objectivepgp_ec_scalar_from_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_from_montgomery
%xdefine __objectivepgp_ec_scalar_inv_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_inv_montgomery
%xdefine __objectivepgp_ec_scalar_inv_montgomery_vartime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_inv_montgomery_vartime
%xdefine __objectivepgp_ec_scalar_is_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_is_zero
%xdefine __objectivepgp_ec_scalar_mul_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_mul_montgomery
%xdefine __objectivepgp_ec_scalar_to_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_to_montgomery
%xdefine __objectivepgp_ec_simple_scalar_inv_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_simple_scalar_inv_montgomery
%xdefine __objectivepgp_gcm_init_4bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_4bit
%xdefine __objectivepgp_gcm_init_ssse3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_ssse3
%xdefine __objectivepgp_kBoringSSLRSASqrtTwo _ %+ BORINGSSL_PREFIX %+ __objectivepgp_kBoringSSLRSASqrtTwo
%xdefine __objectivepgp_kBoringSSLRSASqrtTwoLen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_kBoringSSLRSASqrtTwoLen
%xdefine __objectivepgp_md4_block_data_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_md4_block_data_order
%xdefine __objectivepgp_rsa_default_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_decrypt
%xdefine __objectivepgp_rsa_default_private_transform _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_private_transform
%xdefine __objectivepgp_rsa_default_sign_raw _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_sign_raw
%xdefine __objectivepgp_rsa_default_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_size
%xdefine __objectivepgp_FIPS_mode _ %+ BORINGSSL_PREFIX %+ __objectivepgp_FIPS_mode
%xdefine __objectivepgp_FIPS_mode_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_FIPS_mode_set
%xdefine __objectivepgp_aesni_gcm_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesni_gcm_decrypt
%xdefine __objectivepgp_aesni_gcm_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesni_gcm_encrypt
%xdefine __objectivepgp_aes_hw_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_cbc_encrypt
%xdefine __objectivepgp_aes_hw_ctr32_encrypt_blocks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_ctr32_encrypt_blocks
%xdefine __objectivepgp_aes_hw_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_decrypt
%xdefine __objectivepgp_aes_hw_ecb_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_ecb_encrypt
%xdefine __objectivepgp_aes_hw_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_encrypt
%xdefine __objectivepgp_aes_hw_set_decrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_set_decrypt_key
%xdefine __objectivepgp_aes_hw_set_encrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_set_encrypt_key
%xdefine __objectivepgp_aes_nohw_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_cbc_encrypt
%xdefine __objectivepgp_aes_nohw_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_decrypt
%xdefine __objectivepgp_aes_nohw_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_encrypt
%xdefine __objectivepgp_aes_nohw_set_decrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_set_decrypt_key
%xdefine __objectivepgp_aes_nohw_set_encrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_set_encrypt_key
%xdefine __objectivepgp_gcm_ghash_ssse3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_ssse3
%xdefine __objectivepgp_gcm_gmult_ssse3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_ssse3
%xdefine __objectivepgp_gcm_ghash_4bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_4bit
%xdefine __objectivepgp_gcm_ghash_avx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_avx
%xdefine __objectivepgp_gcm_ghash_clmul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_clmul
%xdefine __objectivepgp_gcm_gmult_4bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_4bit
%xdefine __objectivepgp_gcm_gmult_avx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_avx
%xdefine __objectivepgp_gcm_gmult_clmul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_clmul
%xdefine __objectivepgp_gcm_init_avx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_avx
%xdefine __objectivepgp_gcm_init_clmul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_clmul
%xdefine __objectivepgp_md5_block_asm_data_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_md5_block_asm_data_order
%xdefine __objectivepgp_ecp_nistz256_avx2_select_w7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_avx2_select_w7
%xdefine __objectivepgp_ecp_nistz256_mul_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_mul_mont
%xdefine __objectivepgp_ecp_nistz256_neg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_neg
%xdefine __objectivepgp_ecp_nistz256_ord_mul_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_ord_mul_mont
%xdefine __objectivepgp_ecp_nistz256_ord_sqr_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_ord_sqr_mont
%xdefine __objectivepgp_ecp_nistz256_point_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_add
%xdefine __objectivepgp_ecp_nistz256_point_add_affine _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_add_affine
%xdefine __objectivepgp_ecp_nistz256_point_double _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_double
%xdefine __objectivepgp_ecp_nistz256_select_w5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_select_w5
%xdefine __objectivepgp_ecp_nistz256_select_w7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_select_w7
%xdefine __objectivepgp_ecp_nistz256_sqr_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_sqr_mont
%xdefine __objectivepgp_beeu_mod_inverse_vartime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_beeu_mod_inverse_vartime
%xdefine __objectivepgp_CRYPTO_rdrand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_rdrand
%xdefine __objectivepgp_CRYPTO_rdrand_multiple8_buf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_rdrand_multiple8_buf
%xdefine __objectivepgp_rsaz_1024_gather5_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_gather5_avx2
%xdefine __objectivepgp_rsaz_1024_mul_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_mul_avx2
%xdefine __objectivepgp_rsaz_1024_norm2red_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_norm2red_avx2
%xdefine __objectivepgp_rsaz_1024_red2norm_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_red2norm_avx2
%xdefine __objectivepgp_rsaz_1024_scatter5_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_scatter5_avx2
%xdefine __objectivepgp_rsaz_1024_sqr_avx2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_sqr_avx2
%xdefine __objectivepgp_sha1_block_data_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sha1_block_data_order
%xdefine __objectivepgp_sha256_block_data_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sha256_block_data_order
%xdefine __objectivepgp_sha512_block_data_order _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sha512_block_data_order
%xdefine __objectivepgp_vpaes_cbc_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_cbc_encrypt
%xdefine __objectivepgp_vpaes_ctr32_encrypt_blocks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_ctr32_encrypt_blocks
%xdefine __objectivepgp_vpaes_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_decrypt
%xdefine __objectivepgp_vpaes_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_encrypt
%xdefine __objectivepgp_vpaes_set_decrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_set_decrypt_key
%xdefine __objectivepgp_vpaes_set_encrypt_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_vpaes_set_encrypt_key
%xdefine __objectivepgp_bn_from_montgomery _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_from_montgomery
%xdefine __objectivepgp_bn_gather5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_gather5
%xdefine __objectivepgp_bn_mul_mont_gather5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_mont_gather5
%xdefine __objectivepgp_bn_power5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_power5
%xdefine __objectivepgp_bn_scatter5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_scatter5
%xdefine __objectivepgp_bn_sqr8x_internal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr8x_internal
%xdefine __objectivepgp_bn_sqrx8x_internal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_sqrx8x_internal
%xdefine __objectivepgp_bn_mul_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_mont
%xdefine __objectivepgp_ASN1_BIT_STRING_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_check
%xdefine __objectivepgp_ASN1_BIT_STRING_get_bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_get_bit
%xdefine __objectivepgp_ASN1_BIT_STRING_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_set
%xdefine __objectivepgp_ASN1_BIT_STRING_set_bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_set_bit
%xdefine __objectivepgp_c2i_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_BIT_STRING
%xdefine __objectivepgp_i2c_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2c_ASN1_BIT_STRING
%xdefine __objectivepgp_d2i_ASN1_BOOLEAN _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BOOLEAN
%xdefine __objectivepgp_i2d_ASN1_BOOLEAN _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BOOLEAN
%xdefine __objectivepgp_ASN1_item_d2i_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i_bio
%xdefine __objectivepgp_ASN1_item_d2i_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i_fp
%xdefine __objectivepgp_ASN1_item_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_dup
%xdefine __objectivepgp_ASN1_ENUMERATED_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_get
%xdefine __objectivepgp_ASN1_ENUMERATED_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_set
%xdefine __objectivepgp_ASN1_ENUMERATED_to_BN _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_to_BN
%xdefine __objectivepgp_BN_to_ASN1_ENUMERATED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_to_ASN1_ENUMERATED
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_adj
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_check
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_set
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_set_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_set_string
%xdefine __objectivepgp_asn1_generalizedtime_to_tm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_generalizedtime_to_tm
%xdefine __objectivepgp_ASN1_item_i2d_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d_bio
%xdefine __objectivepgp_ASN1_item_i2d_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d_fp
%xdefine __objectivepgp_ASN1_INTEGER_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_cmp
%xdefine __objectivepgp_ASN1_INTEGER_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_dup
%xdefine __objectivepgp_ASN1_INTEGER_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_get
%xdefine __objectivepgp_ASN1_INTEGER_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_set
%xdefine __objectivepgp_ASN1_INTEGER_set_uint64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_set_uint64
%xdefine __objectivepgp_ASN1_INTEGER_to_BN _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_to_BN
%xdefine __objectivepgp_BN_to_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_to_ASN1_INTEGER
%xdefine __objectivepgp_c2i_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_INTEGER
%xdefine __objectivepgp_i2c_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2c_ASN1_INTEGER
%xdefine __objectivepgp_ASN1_mbstring_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_mbstring_copy
%xdefine __objectivepgp_ASN1_mbstring_ncopy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_mbstring_ncopy
%xdefine __objectivepgp_ASN1_OBJECT_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_create
%xdefine __objectivepgp_ASN1_OBJECT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_free
%xdefine __objectivepgp_ASN1_OBJECT_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_new
%xdefine __objectivepgp_c2i_ASN1_OBJECT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_OBJECT
%xdefine __objectivepgp_d2i_ASN1_OBJECT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_OBJECT
%xdefine __objectivepgp_i2a_ASN1_OBJECT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_OBJECT
%xdefine __objectivepgp_i2d_ASN1_OBJECT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_OBJECT
%xdefine __objectivepgp_i2t_ASN1_OBJECT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2t_ASN1_OBJECT
%xdefine __objectivepgp_ASN1_OCTET_STRING_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_cmp
%xdefine __objectivepgp_ASN1_OCTET_STRING_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_dup
%xdefine __objectivepgp_ASN1_OCTET_STRING_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_set
%xdefine __objectivepgp_ASN1_PRINTABLE_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_type
%xdefine __objectivepgp_ASN1_STRING_TABLE_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_add
%xdefine __objectivepgp_ASN1_STRING_TABLE_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_cleanup
%xdefine __objectivepgp_ASN1_STRING_TABLE_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_get
%xdefine __objectivepgp_ASN1_STRING_get_default_mask _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_get_default_mask
%xdefine __objectivepgp_ASN1_STRING_set_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_by_NID
%xdefine __objectivepgp_ASN1_STRING_set_default_mask _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_default_mask
%xdefine __objectivepgp_ASN1_STRING_set_default_mask_asc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_default_mask_asc
%xdefine __objectivepgp_ASN1_TIME_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_adj
%xdefine __objectivepgp_ASN1_TIME_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_check
%xdefine __objectivepgp_ASN1_TIME_diff _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_diff
%xdefine __objectivepgp_ASN1_TIME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_free
%xdefine __objectivepgp_ASN1_TIME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_it
%xdefine __objectivepgp_ASN1_TIME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_new
%xdefine __objectivepgp_ASN1_TIME_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_set
%xdefine __objectivepgp_ASN1_TIME_set_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_set_string
%xdefine __objectivepgp_ASN1_TIME_to_generalizedtime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_to_generalizedtime
%xdefine __objectivepgp_d2i_ASN1_TIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_TIME
%xdefine __objectivepgp_i2d_ASN1_TIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_TIME
%xdefine __objectivepgp_ASN1_TYPE_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_cmp
%xdefine __objectivepgp_ASN1_TYPE_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_get
%xdefine __objectivepgp_ASN1_TYPE_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_set
%xdefine __objectivepgp_ASN1_TYPE_set1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_set1
%xdefine __objectivepgp_ASN1_UTCTIME_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_adj
%xdefine __objectivepgp_ASN1_UTCTIME_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_check
%xdefine __objectivepgp_ASN1_UTCTIME_cmp_time_t _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_cmp_time_t
%xdefine __objectivepgp_ASN1_UTCTIME_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_set
%xdefine __objectivepgp_ASN1_UTCTIME_set_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_set_string
%xdefine __objectivepgp_asn1_utctime_to_tm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_utctime_to_tm
%xdefine __objectivepgp_UTF8_getc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_UTF8_getc
%xdefine __objectivepgp_UTF8_putc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_UTF8_putc
%xdefine __objectivepgp_ASN1_STRING_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_cmp
%xdefine __objectivepgp_ASN1_STRING_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_copy
%xdefine __objectivepgp_ASN1_STRING_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_data
%xdefine __objectivepgp_ASN1_STRING_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_dup
%xdefine __objectivepgp_ASN1_STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_free
%xdefine __objectivepgp_ASN1_STRING_get0_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_get0_data
%xdefine __objectivepgp_ASN1_STRING_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_length
%xdefine __objectivepgp_ASN1_STRING_length_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_length_set
%xdefine __objectivepgp_ASN1_STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_new
%xdefine __objectivepgp_ASN1_STRING_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set
%xdefine __objectivepgp_ASN1_STRING_set0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set0
%xdefine __objectivepgp_ASN1_STRING_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_type
%xdefine __objectivepgp_ASN1_STRING_type_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_type_new
%xdefine __objectivepgp_ASN1_get_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_get_object
%xdefine __objectivepgp_ASN1_object_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_object_size
%xdefine __objectivepgp_ASN1_put_eoc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_put_eoc
%xdefine __objectivepgp_ASN1_put_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_put_object
%xdefine __objectivepgp_ASN1_tag2str _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_tag2str
%xdefine __objectivepgp_ASN1_item_pack _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_pack
%xdefine __objectivepgp_ASN1_item_unpack _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_unpack
%xdefine __objectivepgp_i2a_ASN1_ENUMERATED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_ENUMERATED
%xdefine __objectivepgp_i2a_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_INTEGER
%xdefine __objectivepgp_i2a_ASN1_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_STRING
%xdefine __objectivepgp_ASN1_item_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i
%xdefine __objectivepgp_ASN1_item_ex_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_d2i
%xdefine __objectivepgp_ASN1_tag2bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_tag2bit
%xdefine __objectivepgp_asn1_ex_c2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_ex_c2i
%xdefine __objectivepgp_ASN1_item_ex_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_i2d
%xdefine __objectivepgp_ASN1_item_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d
%xdefine __objectivepgp_ASN1_item_ndef_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ndef_i2d
%xdefine __objectivepgp_asn1_ex_i2c _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_ex_i2c
%xdefine __objectivepgp_ASN1_item_ex_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_free
%xdefine __objectivepgp_ASN1_item_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_free
%xdefine __objectivepgp_ASN1_primitive_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_primitive_free
%xdefine __objectivepgp_ASN1_template_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_template_free
%xdefine __objectivepgp_asn1_item_combine_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_item_combine_free
%xdefine __objectivepgp_ASN1_item_ex_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_new
%xdefine __objectivepgp_ASN1_item_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_new
%xdefine __objectivepgp_ASN1_primitive_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_primitive_new
%xdefine __objectivepgp_ASN1_template_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_template_new
%xdefine __objectivepgp_ASN1_ANY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ANY_it
%xdefine __objectivepgp_ASN1_BIT_STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_free
%xdefine __objectivepgp_ASN1_BIT_STRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_it
%xdefine __objectivepgp_ASN1_BIT_STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_new
%xdefine __objectivepgp_ASN1_BMPSTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_free
%xdefine __objectivepgp_ASN1_BMPSTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_it
%xdefine __objectivepgp_ASN1_BMPSTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_new
%xdefine __objectivepgp_ASN1_BOOLEAN_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BOOLEAN_it
%xdefine __objectivepgp_ASN1_ENUMERATED_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_free
%xdefine __objectivepgp_ASN1_ENUMERATED_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_it
%xdefine __objectivepgp_ASN1_ENUMERATED_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_new
%xdefine __objectivepgp_ASN1_FBOOLEAN_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_FBOOLEAN_it
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_free
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_it
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_new
%xdefine __objectivepgp_ASN1_GENERALSTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_free
%xdefine __objectivepgp_ASN1_GENERALSTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_it
%xdefine __objectivepgp_ASN1_GENERALSTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_new
%xdefine __objectivepgp_ASN1_IA5STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_free
%xdefine __objectivepgp_ASN1_IA5STRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_it
%xdefine __objectivepgp_ASN1_IA5STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_new
%xdefine __objectivepgp_ASN1_INTEGER_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_free
%xdefine __objectivepgp_ASN1_INTEGER_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_it
%xdefine __objectivepgp_ASN1_INTEGER_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_new
%xdefine __objectivepgp_ASN1_NULL_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_free
%xdefine __objectivepgp_ASN1_NULL_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_it
%xdefine __objectivepgp_ASN1_NULL_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_new
%xdefine __objectivepgp_ASN1_OBJECT_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_it
%xdefine __objectivepgp_ASN1_OCTET_STRING_NDEF_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_NDEF_it
%xdefine __objectivepgp_ASN1_OCTET_STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_free
%xdefine __objectivepgp_ASN1_OCTET_STRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_it
%xdefine __objectivepgp_ASN1_OCTET_STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_new
%xdefine __objectivepgp_ASN1_PRINTABLESTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_free
%xdefine __objectivepgp_ASN1_PRINTABLESTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_it
%xdefine __objectivepgp_ASN1_PRINTABLESTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_new
%xdefine __objectivepgp_ASN1_PRINTABLE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_free
%xdefine __objectivepgp_ASN1_PRINTABLE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_it
%xdefine __objectivepgp_ASN1_PRINTABLE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_new
%xdefine __objectivepgp_ASN1_SEQUENCE_ANY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SEQUENCE_ANY_it
%xdefine __objectivepgp_ASN1_SEQUENCE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SEQUENCE_it
%xdefine __objectivepgp_ASN1_SET_ANY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SET_ANY_it
%xdefine __objectivepgp_ASN1_T61STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_free
%xdefine __objectivepgp_ASN1_T61STRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_it
%xdefine __objectivepgp_ASN1_T61STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_new
%xdefine __objectivepgp_ASN1_TBOOLEAN_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TBOOLEAN_it
%xdefine __objectivepgp_ASN1_TYPE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_free
%xdefine __objectivepgp_ASN1_TYPE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_new
%xdefine __objectivepgp_ASN1_UNIVERSALSTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_free
%xdefine __objectivepgp_ASN1_UNIVERSALSTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_it
%xdefine __objectivepgp_ASN1_UNIVERSALSTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_new
%xdefine __objectivepgp_ASN1_UTCTIME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_free
%xdefine __objectivepgp_ASN1_UTCTIME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_it
%xdefine __objectivepgp_ASN1_UTCTIME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_new
%xdefine __objectivepgp_ASN1_UTF8STRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_free
%xdefine __objectivepgp_ASN1_UTF8STRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_it
%xdefine __objectivepgp_ASN1_UTF8STRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_new
%xdefine __objectivepgp_ASN1_VISIBLESTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_free
%xdefine __objectivepgp_ASN1_VISIBLESTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_it
%xdefine __objectivepgp_ASN1_VISIBLESTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_new
%xdefine __objectivepgp_DIRECTORYSTRING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_free
%xdefine __objectivepgp_DIRECTORYSTRING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_it
%xdefine __objectivepgp_DIRECTORYSTRING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_new
%xdefine __objectivepgp_DISPLAYTEXT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_free
%xdefine __objectivepgp_DISPLAYTEXT_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_it
%xdefine __objectivepgp_DISPLAYTEXT_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_new
%xdefine __objectivepgp_d2i_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BIT_STRING
%xdefine __objectivepgp_d2i_ASN1_BMPSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BMPSTRING
%xdefine __objectivepgp_d2i_ASN1_ENUMERATED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_ENUMERATED
%xdefine __objectivepgp_d2i_ASN1_GENERALIZEDTIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_GENERALIZEDTIME
%xdefine __objectivepgp_d2i_ASN1_GENERALSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_GENERALSTRING
%xdefine __objectivepgp_d2i_ASN1_IA5STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_IA5STRING
%xdefine __objectivepgp_d2i_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_INTEGER
%xdefine __objectivepgp_d2i_ASN1_NULL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_NULL
%xdefine __objectivepgp_d2i_ASN1_OCTET_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_OCTET_STRING
%xdefine __objectivepgp_d2i_ASN1_PRINTABLE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_PRINTABLE
%xdefine __objectivepgp_d2i_ASN1_PRINTABLESTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_PRINTABLESTRING
%xdefine __objectivepgp_d2i_ASN1_SEQUENCE_ANY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_SEQUENCE_ANY
%xdefine __objectivepgp_d2i_ASN1_SET_ANY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_SET_ANY
%xdefine __objectivepgp_d2i_ASN1_T61STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_T61STRING
%xdefine __objectivepgp_d2i_ASN1_TYPE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_TYPE
%xdefine __objectivepgp_d2i_ASN1_UNIVERSALSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UNIVERSALSTRING
%xdefine __objectivepgp_d2i_ASN1_UTCTIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UTCTIME
%xdefine __objectivepgp_d2i_ASN1_UTF8STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UTF8STRING
%xdefine __objectivepgp_d2i_ASN1_VISIBLESTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_VISIBLESTRING
%xdefine __objectivepgp_d2i_DIRECTORYSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIRECTORYSTRING
%xdefine __objectivepgp_d2i_DISPLAYTEXT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DISPLAYTEXT
%xdefine __objectivepgp_i2d_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BIT_STRING
%xdefine __objectivepgp_i2d_ASN1_BMPSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BMPSTRING
%xdefine __objectivepgp_i2d_ASN1_ENUMERATED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_ENUMERATED
%xdefine __objectivepgp_i2d_ASN1_GENERALIZEDTIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_GENERALIZEDTIME
%xdefine __objectivepgp_i2d_ASN1_GENERALSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_GENERALSTRING
%xdefine __objectivepgp_i2d_ASN1_IA5STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_IA5STRING
%xdefine __objectivepgp_i2d_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_INTEGER
%xdefine __objectivepgp_i2d_ASN1_NULL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_NULL
%xdefine __objectivepgp_i2d_ASN1_OCTET_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_OCTET_STRING
%xdefine __objectivepgp_i2d_ASN1_PRINTABLE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_PRINTABLE
%xdefine __objectivepgp_i2d_ASN1_PRINTABLESTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_PRINTABLESTRING
%xdefine __objectivepgp_i2d_ASN1_SEQUENCE_ANY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_SEQUENCE_ANY
%xdefine __objectivepgp_i2d_ASN1_SET_ANY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_SET_ANY
%xdefine __objectivepgp_i2d_ASN1_T61STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_T61STRING
%xdefine __objectivepgp_i2d_ASN1_TYPE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_TYPE
%xdefine __objectivepgp_i2d_ASN1_UNIVERSALSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UNIVERSALSTRING
%xdefine __objectivepgp_i2d_ASN1_UTCTIME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UTCTIME
%xdefine __objectivepgp_i2d_ASN1_UTF8STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UTF8STRING
%xdefine __objectivepgp_i2d_ASN1_VISIBLESTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_VISIBLESTRING
%xdefine __objectivepgp_i2d_DIRECTORYSTRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIRECTORYSTRING
%xdefine __objectivepgp_i2d_DISPLAYTEXT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DISPLAYTEXT
%xdefine __objectivepgp_asn1_do_adb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_do_adb
%xdefine __objectivepgp_asn1_enc_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_free
%xdefine __objectivepgp_asn1_enc_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_init
%xdefine __objectivepgp_asn1_enc_restore _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_restore
%xdefine __objectivepgp_asn1_enc_save _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_save
%xdefine __objectivepgp_asn1_get_choice_selector _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_get_choice_selector
%xdefine __objectivepgp_asn1_get_field_ptr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_get_field_ptr
%xdefine __objectivepgp_asn1_refcount_dec_and_test_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_refcount_dec_and_test_zero
%xdefine __objectivepgp_asn1_refcount_set_one _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_refcount_set_one
%xdefine __objectivepgp_asn1_set_choice_selector _ %+ BORINGSSL_PREFIX %+ __objectivepgp_asn1_set_choice_selector
%xdefine __objectivepgp_OPENSSL_gmtime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime
%xdefine __objectivepgp_OPENSSL_gmtime_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime_adj
%xdefine __objectivepgp_OPENSSL_gmtime_diff _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime_diff
%xdefine __objectivepgp_EVP_DecodeBase64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeBase64
%xdefine __objectivepgp_EVP_DecodeBlock _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeBlock
%xdefine __objectivepgp_EVP_DecodeFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeFinal
%xdefine __objectivepgp_EVP_DecodeInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeInit
%xdefine __objectivepgp_EVP_DecodeUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeUpdate
%xdefine __objectivepgp_EVP_DecodedLength _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodedLength
%xdefine __objectivepgp_EVP_EncodeBlock _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeBlock
%xdefine __objectivepgp_EVP_EncodeFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeFinal
%xdefine __objectivepgp_EVP_EncodeInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeInit
%xdefine __objectivepgp_EVP_EncodeUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeUpdate
%xdefine __objectivepgp_EVP_EncodedLength _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodedLength
%xdefine __objectivepgp_BIO_callback_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_callback_ctrl
%xdefine __objectivepgp_BIO_clear_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_clear_flags
%xdefine __objectivepgp_BIO_clear_retry_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_clear_retry_flags
%xdefine __objectivepgp_BIO_copy_next_retry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_copy_next_retry
%xdefine __objectivepgp_BIO_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl
%xdefine __objectivepgp_BIO_ctrl_pending _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_pending
%xdefine __objectivepgp_BIO_eof _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_eof
%xdefine __objectivepgp_BIO_find_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_find_type
%xdefine __objectivepgp_BIO_flush _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_flush
%xdefine __objectivepgp_BIO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_free
%xdefine __objectivepgp_BIO_free_all _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_free_all
%xdefine __objectivepgp_BIO_get_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_data
%xdefine __objectivepgp_BIO_get_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_init
%xdefine __objectivepgp_BIO_get_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_new_index
%xdefine __objectivepgp_BIO_get_retry_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_retry_flags
%xdefine __objectivepgp_BIO_get_retry_reason _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_retry_reason
%xdefine __objectivepgp_BIO_get_shutdown _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_shutdown
%xdefine __objectivepgp_BIO_gets _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_gets
%xdefine __objectivepgp_BIO_indent _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_indent
%xdefine __objectivepgp_BIO_int_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_int_ctrl
%xdefine __objectivepgp_BIO_meth_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_free
%xdefine __objectivepgp_BIO_meth_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_new
%xdefine __objectivepgp_BIO_meth_set_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_create
%xdefine __objectivepgp_BIO_meth_set_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_ctrl
%xdefine __objectivepgp_BIO_meth_set_destroy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_destroy
%xdefine __objectivepgp_BIO_meth_set_gets _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_gets
%xdefine __objectivepgp_BIO_meth_set_puts _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_puts
%xdefine __objectivepgp_BIO_meth_set_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_read
%xdefine __objectivepgp_BIO_meth_set_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_write
%xdefine __objectivepgp_BIO_method_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_method_type
%xdefine __objectivepgp_BIO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new
%xdefine __objectivepgp_BIO_next _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_next
%xdefine __objectivepgp_BIO_number_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_number_read
%xdefine __objectivepgp_BIO_number_written _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_number_written
%xdefine __objectivepgp_BIO_pending _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_pending
%xdefine __objectivepgp_BIO_pop _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_pop
%xdefine __objectivepgp_BIO_ptr_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_ptr_ctrl
%xdefine __objectivepgp_BIO_push _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_push
%xdefine __objectivepgp_BIO_puts _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_puts
%xdefine __objectivepgp_BIO_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_read
%xdefine __objectivepgp_BIO_read_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_read_asn1
%xdefine __objectivepgp_BIO_reset _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_reset
%xdefine __objectivepgp_BIO_set_close _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_close
%xdefine __objectivepgp_BIO_set_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_data
%xdefine __objectivepgp_BIO_set_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_flags
%xdefine __objectivepgp_BIO_set_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_init
%xdefine __objectivepgp_BIO_set_retry_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_read
%xdefine __objectivepgp_BIO_set_retry_special _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_special
%xdefine __objectivepgp_BIO_set_retry_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_write
%xdefine __objectivepgp_BIO_set_shutdown _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_shutdown
%xdefine __objectivepgp_BIO_set_write_buffer_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_write_buffer_size
%xdefine __objectivepgp_BIO_should_io_special _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_io_special
%xdefine __objectivepgp_BIO_should_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_read
%xdefine __objectivepgp_BIO_should_retry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_retry
%xdefine __objectivepgp_BIO_should_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_write
%xdefine __objectivepgp_BIO_test_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_test_flags
%xdefine __objectivepgp_BIO_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_up_ref
%xdefine __objectivepgp_BIO_vfree _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_vfree
%xdefine __objectivepgp_BIO_wpending _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_wpending
%xdefine __objectivepgp_BIO_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_write
%xdefine __objectivepgp_BIO_write_all _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_write_all
%xdefine __objectivepgp_ERR_print_errors _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors
%xdefine __objectivepgp_BIO_get_mem_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_mem_data
%xdefine __objectivepgp_BIO_get_mem_ptr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_mem_ptr
%xdefine __objectivepgp_BIO_mem_contents _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_mem_contents
%xdefine __objectivepgp_BIO_new_mem_buf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_mem_buf
%xdefine __objectivepgp_BIO_s_mem _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_mem
%xdefine __objectivepgp_BIO_set_mem_buf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_mem_buf
%xdefine __objectivepgp_BIO_set_mem_eof_return _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_mem_eof_return
%xdefine __objectivepgp_BIO_do_connect _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_do_connect
%xdefine __objectivepgp_BIO_new_connect _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_connect
%xdefine __objectivepgp_BIO_s_connect _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_connect
%xdefine __objectivepgp_BIO_set_conn_hostname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_hostname
%xdefine __objectivepgp_BIO_set_conn_int_port _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_int_port
%xdefine __objectivepgp_BIO_set_conn_port _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_port
%xdefine __objectivepgp_BIO_set_nbio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_nbio
%xdefine __objectivepgp_BIO_get_fd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_fd
%xdefine __objectivepgp_BIO_new_fd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_fd
%xdefine __objectivepgp_BIO_s_fd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_fd
%xdefine __objectivepgp_BIO_set_fd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_fd
%xdefine __objectivepgp_bio_fd_should_retry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bio_fd_should_retry
%xdefine __objectivepgp_BIO_append_filename _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_append_filename
%xdefine __objectivepgp_BIO_get_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_fp
%xdefine __objectivepgp_BIO_new_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_file
%xdefine __objectivepgp_BIO_new_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_fp
%xdefine __objectivepgp_BIO_read_filename _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_read_filename
%xdefine __objectivepgp_BIO_rw_filename _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_rw_filename
%xdefine __objectivepgp_BIO_s_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_file
%xdefine __objectivepgp_BIO_set_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_fp
%xdefine __objectivepgp_BIO_write_filename _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_write_filename
%xdefine __objectivepgp_BIO_hexdump _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_hexdump
%xdefine __objectivepgp_BIO_ctrl_get_read_request _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_get_read_request
%xdefine __objectivepgp_BIO_ctrl_get_write_guarantee _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_get_write_guarantee
%xdefine __objectivepgp_BIO_new_bio_pair _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_bio_pair
%xdefine __objectivepgp_BIO_shutdown_wr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_shutdown_wr
%xdefine __objectivepgp_BIO_printf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_printf
%xdefine __objectivepgp_BIO_new_socket _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_socket
%xdefine __objectivepgp_BIO_s_socket _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_socket
%xdefine __objectivepgp_bio_clear_socket_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bio_clear_socket_error
%xdefine __objectivepgp_bio_ip_and_port_to_socket_and_addr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bio_ip_and_port_to_socket_and_addr
%xdefine __objectivepgp_bio_sock_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bio_sock_error
%xdefine __objectivepgp_bio_socket_nbio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_bio_socket_nbio
%xdefine __objectivepgp_BN_marshal_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_marshal_asn1
%xdefine __objectivepgp_BN_parse_asn1_unsigned _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_parse_asn1_unsigned
%xdefine __objectivepgp_BN_asc2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_asc2bn
%xdefine __objectivepgp_BN_bn2binpad _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2binpad
%xdefine __objectivepgp_BN_bn2cbb_padded _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2cbb_padded
%xdefine __objectivepgp_BN_bn2dec _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2dec
%xdefine __objectivepgp_BN_bn2hex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2hex
%xdefine __objectivepgp_BN_bn2mpi _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2mpi
%xdefine __objectivepgp_BN_dec2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_dec2bn
%xdefine __objectivepgp_BN_hex2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_hex2bn
%xdefine __objectivepgp_BN_mpi2bn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_mpi2bn
%xdefine __objectivepgp_BN_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_print
%xdefine __objectivepgp_BN_print_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_print_fp
%xdefine __objectivepgp_BUF_MEM_append _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_append
%xdefine __objectivepgp_BUF_MEM_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_free
%xdefine __objectivepgp_BUF_MEM_grow _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_grow
%xdefine __objectivepgp_BUF_MEM_grow_clean _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_grow_clean
%xdefine __objectivepgp_BUF_MEM_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_new
%xdefine __objectivepgp_BUF_MEM_reserve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_reserve
%xdefine __objectivepgp_BUF_memdup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_memdup
%xdefine __objectivepgp_BUF_strdup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_strdup
%xdefine __objectivepgp_BUF_strlcat _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_strlcat
%xdefine __objectivepgp_BUF_strlcpy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_strlcpy
%xdefine __objectivepgp_BUF_strndup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_strndup
%xdefine __objectivepgp_BUF_strnlen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BUF_strnlen
%xdefine __objectivepgp_CBB_finish_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_finish_i2d
%xdefine __objectivepgp_CBS_asn1_ber_to_der _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_ber_to_der
%xdefine __objectivepgp_CBS_get_asn1_implicit_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_implicit_string
%xdefine __objectivepgp_CBB_add_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1
%xdefine __objectivepgp_CBB_add_asn1_bool _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_bool
%xdefine __objectivepgp_CBB_add_asn1_octet_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_octet_string
%xdefine __objectivepgp_CBB_add_asn1_oid_from_text _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_oid_from_text
%xdefine __objectivepgp_CBB_add_asn1_uint64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_uint64
%xdefine __objectivepgp_CBB_add_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_bytes
%xdefine __objectivepgp_CBB_add_space _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_space
%xdefine __objectivepgp_CBB_add_u16 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u16
%xdefine __objectivepgp_CBB_add_u16_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u16_length_prefixed
%xdefine __objectivepgp_CBB_add_u24 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u24
%xdefine __objectivepgp_CBB_add_u24_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u24_length_prefixed
%xdefine __objectivepgp_CBB_add_u32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u32
%xdefine __objectivepgp_CBB_add_u64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u64
%xdefine __objectivepgp_CBB_add_u8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u8
%xdefine __objectivepgp_CBB_add_u8_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u8_length_prefixed
%xdefine __objectivepgp_CBB_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_cleanup
%xdefine __objectivepgp_CBB_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_data
%xdefine __objectivepgp_CBB_did_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_did_write
%xdefine __objectivepgp_CBB_discard_child _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_discard_child
%xdefine __objectivepgp_CBB_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_finish
%xdefine __objectivepgp_CBB_flush _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_flush
%xdefine __objectivepgp_CBB_flush_asn1_set_of _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_flush_asn1_set_of
%xdefine __objectivepgp_CBB_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_init
%xdefine __objectivepgp_CBB_init_fixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_init_fixed
%xdefine __objectivepgp_CBB_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_len
%xdefine __objectivepgp_CBB_reserve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_reserve
%xdefine __objectivepgp_CBB_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBB_zero
%xdefine __objectivepgp_CBS_asn1_bitstring_has_bit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_bitstring_has_bit
%xdefine __objectivepgp_CBS_asn1_oid_to_text _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_oid_to_text
%xdefine __objectivepgp_CBS_contains_zero_byte _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_contains_zero_byte
%xdefine __objectivepgp_CBS_copy_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_copy_bytes
%xdefine __objectivepgp_CBS_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_data
%xdefine __objectivepgp_CBS_get_any_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_asn1
%xdefine __objectivepgp_CBS_get_any_asn1_element _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_asn1_element
%xdefine __objectivepgp_CBS_get_any_ber_asn1_element _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_ber_asn1_element
%xdefine __objectivepgp_CBS_get_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1
%xdefine __objectivepgp_CBS_get_asn1_bool _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_bool
%xdefine __objectivepgp_CBS_get_asn1_element _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_element
%xdefine __objectivepgp_CBS_get_asn1_uint64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_uint64
%xdefine __objectivepgp_CBS_get_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_bytes
%xdefine __objectivepgp_CBS_get_last_u8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_last_u8
%xdefine __objectivepgp_CBS_get_optional_asn1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1
%xdefine __objectivepgp_CBS_get_optional_asn1_bool _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_bool
%xdefine __objectivepgp_CBS_get_optional_asn1_octet_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_octet_string
%xdefine __objectivepgp_CBS_get_optional_asn1_uint64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_uint64
%xdefine __objectivepgp_CBS_get_u16 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u16
%xdefine __objectivepgp_CBS_get_u16_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u16_length_prefixed
%xdefine __objectivepgp_CBS_get_u24 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u24
%xdefine __objectivepgp_CBS_get_u24_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u24_length_prefixed
%xdefine __objectivepgp_CBS_get_u32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u32
%xdefine __objectivepgp_CBS_get_u64 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u64
%xdefine __objectivepgp_CBS_get_u8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u8
%xdefine __objectivepgp_CBS_get_u8_length_prefixed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u8_length_prefixed
%xdefine __objectivepgp_CBS_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_init
%xdefine __objectivepgp_CBS_is_valid_asn1_bitstring _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_is_valid_asn1_bitstring
%xdefine __objectivepgp_CBS_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_len
%xdefine __objectivepgp_CBS_mem_equal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_mem_equal
%xdefine __objectivepgp_CBS_peek_asn1_tag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_peek_asn1_tag
%xdefine __objectivepgp_CBS_skip _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_skip
%xdefine __objectivepgp_CBS_stow _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_stow
%xdefine __objectivepgp_CBS_strdup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CBS_strdup
%xdefine __objectivepgp_cbb_add_latin1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_latin1
%xdefine __objectivepgp_cbb_add_ucs2_be _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_ucs2_be
%xdefine __objectivepgp_cbb_add_utf32_be _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_utf32_be
%xdefine __objectivepgp_cbb_add_utf8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_utf8
%xdefine __objectivepgp_cbb_get_utf8_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbb_get_utf8_len
%xdefine __objectivepgp_cbs_get_latin1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_latin1
%xdefine __objectivepgp_cbs_get_ucs2_be _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_ucs2_be
%xdefine __objectivepgp_cbs_get_utf32_be _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_utf32_be
%xdefine __objectivepgp_cbs_get_utf8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_utf8
%xdefine __objectivepgp_CRYPTO_chacha_20 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_chacha_20
%xdefine __objectivepgp_CRYPTO_hchacha20 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_hchacha20
%xdefine __objectivepgp_EVP_get_cipherbyname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_cipherbyname
%xdefine __objectivepgp_EVP_get_cipherbynid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_cipherbynid
%xdefine __objectivepgp_EVP_BytesToKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_BytesToKey
%xdefine __objectivepgp_EVP_aead_aes_128_ccm_bluetooth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ccm_bluetooth
%xdefine __objectivepgp_EVP_aead_aes_128_ccm_bluetooth_8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ccm_bluetooth_8
%xdefine __objectivepgp_EVP_aead_aes_128_ctr_hmac_sha256 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ctr_hmac_sha256
%xdefine __objectivepgp_EVP_aead_aes_256_ctr_hmac_sha256 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_ctr_hmac_sha256
%xdefine __objectivepgp_EVP_aead_aes_128_gcm_siv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_siv
%xdefine __objectivepgp_EVP_aead_aes_256_gcm_siv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_siv
%xdefine __objectivepgp_EVP_aead_chacha20_poly1305 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_chacha20_poly1305
%xdefine __objectivepgp_EVP_aead_xchacha20_poly1305 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_xchacha20_poly1305
%xdefine __objectivepgp_EVP_enc_null _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_enc_null
%xdefine __objectivepgp_EVP_rc2_40_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc2_40_cbc
%xdefine __objectivepgp_EVP_rc2_cbc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc2_cbc
%xdefine __objectivepgp_EVP_rc4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc4
%xdefine __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls
%xdefine __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls_implicit_iv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls_implicit_iv
%xdefine __objectivepgp_EVP_aead_aes_128_cbc_sha256_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha256_tls
%xdefine __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls
%xdefine __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls_implicit_iv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls_implicit_iv
%xdefine __objectivepgp_EVP_aead_aes_256_cbc_sha256_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha256_tls
%xdefine __objectivepgp_EVP_aead_aes_256_cbc_sha384_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha384_tls
%xdefine __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls
%xdefine __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv
%xdefine __objectivepgp_EVP_aead_null_sha1_tls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_null_sha1_tls
%xdefine __objectivepgp_EVP_tls_cbc_copy_mac _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_copy_mac
%xdefine __objectivepgp_EVP_tls_cbc_digest_record _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_digest_record
%xdefine __objectivepgp_EVP_tls_cbc_record_digest_supported _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_record_digest_supported
%xdefine __objectivepgp_EVP_tls_cbc_remove_padding _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_remove_padding
%xdefine __objectivepgp_AES_CMAC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AES_CMAC
%xdefine __objectivepgp_CMAC_CTX_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_copy
%xdefine __objectivepgp_CMAC_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_free
%xdefine __objectivepgp_CMAC_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_new
%xdefine __objectivepgp_CMAC_Final _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Final
%xdefine __objectivepgp_CMAC_Init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Init
%xdefine __objectivepgp_CMAC_Reset _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Reset
%xdefine __objectivepgp_CMAC_Update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Update
%xdefine __objectivepgp_CONF_VALUE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CONF_VALUE_new
%xdefine __objectivepgp_CONF_modules_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CONF_modules_free
%xdefine __objectivepgp_CONF_modules_load_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CONF_modules_load_file
%xdefine __objectivepgp_CONF_parse_list _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CONF_parse_list
%xdefine __objectivepgp_NCONF_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_free
%xdefine __objectivepgp_NCONF_get_section _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_get_section
%xdefine __objectivepgp_NCONF_get_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_get_string
%xdefine __objectivepgp_NCONF_load _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_load
%xdefine __objectivepgp_NCONF_load_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_load_bio
%xdefine __objectivepgp_NCONF_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NCONF_new
%xdefine __objectivepgp_OPENSSL_config _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_config
%xdefine __objectivepgp_OPENSSL_no_config _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_no_config
%xdefine __objectivepgp_OPENSSL_cpuid_setup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cpuid_setup
%xdefine __objectivepgp_CRYPTO_has_asm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_has_asm
%xdefine __objectivepgp_CRYPTO_is_confidential_build _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_is_confidential_build
%xdefine __objectivepgp_CRYPTO_library_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_library_init
%xdefine __objectivepgp_CRYPTO_malloc_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_malloc_init
%xdefine __objectivepgp_ENGINE_load_builtin_engines _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_load_builtin_engines
%xdefine __objectivepgp_ENGINE_register_all_complete _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_register_all_complete
%xdefine __objectivepgp_OPENSSL_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cleanup
%xdefine __objectivepgp_OPENSSL_ia32cap_P _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_ia32cap_P
%xdefine __objectivepgp_OPENSSL_init_crypto _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_init_crypto
%xdefine __objectivepgp_OPENSSL_load_builtin_modules _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_load_builtin_modules
%xdefine __objectivepgp_OPENSSL_malloc_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_malloc_init
%xdefine __objectivepgp_OpenSSL_version _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_version
%xdefine __objectivepgp_OpenSSL_version_num _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_version_num
%xdefine __objectivepgp_SSLeay _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SSLeay
%xdefine __objectivepgp_SSLeay_version _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SSLeay_version
%xdefine __objectivepgp_SPAKE2_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_CTX_free
%xdefine __objectivepgp_SPAKE2_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_CTX_new
%xdefine __objectivepgp_SPAKE2_generate_msg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_generate_msg
%xdefine __objectivepgp_SPAKE2_process_msg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_process_msg
%xdefine __objectivepgp_DH_compute_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_compute_key
%xdefine __objectivepgp_DH_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_free
%xdefine __objectivepgp_DH_generate_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_generate_key
%xdefine __objectivepgp_DH_generate_parameters_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_generate_parameters_ex
%xdefine __objectivepgp_DH_get0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_get0_key
%xdefine __objectivepgp_DH_get0_pqg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_get0_pqg
%xdefine __objectivepgp_DH_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_get_ex_data
%xdefine __objectivepgp_DH_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_get_ex_new_index
%xdefine __objectivepgp_DH_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_new
%xdefine __objectivepgp_DH_num_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_num_bits
%xdefine __objectivepgp_DH_set0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_set0_key
%xdefine __objectivepgp_DH_set0_pqg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_set0_pqg
%xdefine __objectivepgp_DH_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_set_ex_data
%xdefine __objectivepgp_DH_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_size
%xdefine __objectivepgp_DH_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_up_ref
%xdefine __objectivepgp_DHparams_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DHparams_dup
%xdefine __objectivepgp_BN_get_rfc3526_prime_1536 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BN_get_rfc3526_prime_1536
%xdefine __objectivepgp_DH_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_check
%xdefine __objectivepgp_DH_check_pub_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_check_pub_key
%xdefine __objectivepgp_DH_marshal_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_marshal_parameters
%xdefine __objectivepgp_DH_parse_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DH_parse_parameters
%xdefine __objectivepgp_d2i_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DHparams
%xdefine __objectivepgp_i2d_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DHparams
%xdefine __objectivepgp_EVP_get_digestbyname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbyname
%xdefine __objectivepgp_EVP_get_digestbynid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbynid
%xdefine __objectivepgp_EVP_get_digestbyobj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbyobj
%xdefine __objectivepgp_EVP_marshal_digest_algorithm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_digest_algorithm
%xdefine __objectivepgp_EVP_parse_digest_algorithm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_digest_algorithm
%xdefine __objectivepgp_DSA_SIG_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_free
%xdefine __objectivepgp_DSA_SIG_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_new
%xdefine __objectivepgp_DSA_check_signature _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_check_signature
%xdefine __objectivepgp_DSA_do_check_signature _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_check_signature
%xdefine __objectivepgp_DSA_do_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_sign
%xdefine __objectivepgp_DSA_do_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_verify
%xdefine __objectivepgp_DSA_dup_DH _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_dup_DH
%xdefine __objectivepgp_DSA_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_free
%xdefine __objectivepgp_DSA_generate_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_generate_key
%xdefine __objectivepgp_DSA_generate_parameters_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_generate_parameters_ex
%xdefine __objectivepgp_DSA_get0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_get0_key
%xdefine __objectivepgp_DSA_get0_pqg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_get0_pqg
%xdefine __objectivepgp_DSA_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_get_ex_data
%xdefine __objectivepgp_DSA_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_get_ex_new_index
%xdefine __objectivepgp_DSA_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_new
%xdefine __objectivepgp_DSA_set0_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_set0_key
%xdefine __objectivepgp_DSA_set0_pqg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_set0_pqg
%xdefine __objectivepgp_DSA_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_set_ex_data
%xdefine __objectivepgp_DSA_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_sign
%xdefine __objectivepgp_DSA_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_size
%xdefine __objectivepgp_DSA_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_up_ref
%xdefine __objectivepgp_DSA_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_verify
%xdefine __objectivepgp_DSAparams_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSAparams_dup
%xdefine __objectivepgp_DSA_SIG_marshal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_marshal
%xdefine __objectivepgp_DSA_SIG_parse _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_parse
%xdefine __objectivepgp_DSA_marshal_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_parameters
%xdefine __objectivepgp_DSA_marshal_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_private_key
%xdefine __objectivepgp_DSA_marshal_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_public_key
%xdefine __objectivepgp_DSA_parse_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_parameters
%xdefine __objectivepgp_DSA_parse_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_private_key
%xdefine __objectivepgp_DSA_parse_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_public_key
%xdefine __objectivepgp_d2i_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey
%xdefine __objectivepgp_d2i_DSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPublicKey
%xdefine __objectivepgp_d2i_DSA_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_SIG
%xdefine __objectivepgp_d2i_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAparams
%xdefine __objectivepgp_i2d_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey
%xdefine __objectivepgp_i2d_DSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPublicKey
%xdefine __objectivepgp_i2d_DSA_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_SIG
%xdefine __objectivepgp_i2d_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAparams
%xdefine __objectivepgp_ECDH_compute_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDH_compute_key
%xdefine __objectivepgp_ECDSA_SIG_from_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_from_bytes
%xdefine __objectivepgp_ECDSA_SIG_marshal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_marshal
%xdefine __objectivepgp_ECDSA_SIG_max_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_max_len
%xdefine __objectivepgp_ECDSA_SIG_parse _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_parse
%xdefine __objectivepgp_ECDSA_SIG_to_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_to_bytes
%xdefine __objectivepgp_ECDSA_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_sign
%xdefine __objectivepgp_ECDSA_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_size
%xdefine __objectivepgp_ECDSA_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_verify
%xdefine __objectivepgp_d2i_ECDSA_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECDSA_SIG
%xdefine __objectivepgp_i2d_ECDSA_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECDSA_SIG
%xdefine __objectivepgp_EC_KEY_marshal_curve_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_marshal_curve_name
%xdefine __objectivepgp_EC_KEY_marshal_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_marshal_private_key
%xdefine __objectivepgp_EC_KEY_parse_curve_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_curve_name
%xdefine __objectivepgp_EC_KEY_parse_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_parameters
%xdefine __objectivepgp_EC_KEY_parse_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_private_key
%xdefine __objectivepgp_EC_POINT_point2cbb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_point2cbb
%xdefine __objectivepgp_d2i_ECParameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECParameters
%xdefine __objectivepgp_d2i_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey
%xdefine __objectivepgp_i2d_ECParameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECParameters
%xdefine __objectivepgp_i2d_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey
%xdefine __objectivepgp_i2o_ECPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2o_ECPublicKey
%xdefine __objectivepgp_o2i_ECPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_o2i_ECPublicKey
%xdefine __objectivepgp_ERR_SAVE_STATE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_SAVE_STATE_free
%xdefine __objectivepgp_ERR_add_error_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_add_error_data
%xdefine __objectivepgp_ERR_add_error_dataf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_add_error_dataf
%xdefine __objectivepgp_ERR_clear_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_clear_error
%xdefine __objectivepgp_ERR_clear_system_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_clear_system_error
%xdefine __objectivepgp_ERR_error_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_error_string
%xdefine __objectivepgp_ERR_error_string_n _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_error_string_n
%xdefine __objectivepgp_ERR_free_strings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_free_strings
%xdefine __objectivepgp_ERR_func_error_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_func_error_string
%xdefine __objectivepgp_ERR_get_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error
%xdefine __objectivepgp_ERR_get_error_line _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error_line
%xdefine __objectivepgp_ERR_get_error_line_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error_line_data
%xdefine __objectivepgp_ERR_get_next_error_library _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_next_error_library
%xdefine __objectivepgp_ERR_lib_error_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_lib_error_string
%xdefine __objectivepgp_ERR_load_BIO_strings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_BIO_strings
%xdefine __objectivepgp_ERR_load_ERR_strings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_ERR_strings
%xdefine __objectivepgp_ERR_load_RAND_strings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_RAND_strings
%xdefine __objectivepgp_ERR_load_crypto_strings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_crypto_strings
%xdefine __objectivepgp_ERR_peek_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error
%xdefine __objectivepgp_ERR_peek_error_line _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error_line
%xdefine __objectivepgp_ERR_peek_error_line_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error_line_data
%xdefine __objectivepgp_ERR_peek_last_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error
%xdefine __objectivepgp_ERR_peek_last_error_line _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error_line
%xdefine __objectivepgp_ERR_peek_last_error_line_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error_line_data
%xdefine __objectivepgp_ERR_pop_to_mark _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_pop_to_mark
%xdefine __objectivepgp_ERR_print_errors_cb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors_cb
%xdefine __objectivepgp_ERR_print_errors_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors_fp
%xdefine __objectivepgp_ERR_put_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_put_error
%xdefine __objectivepgp_ERR_reason_error_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_reason_error_string
%xdefine __objectivepgp_ERR_remove_state _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_remove_state
%xdefine __objectivepgp_ERR_remove_thread_state _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_remove_thread_state
%xdefine __objectivepgp_ERR_restore_state _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_restore_state
%xdefine __objectivepgp_ERR_save_state _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_save_state
%xdefine __objectivepgp_ERR_set_mark _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ERR_set_mark
%xdefine __objectivepgp_kOpenSSLReasonStringData _ %+ BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonStringData
%xdefine __objectivepgp_kOpenSSLReasonValues _ %+ BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonValues
%xdefine __objectivepgp_kOpenSSLReasonValuesLen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonValuesLen
%xdefine __objectivepgp_ENGINE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_free
%xdefine __objectivepgp_ENGINE_get_ECDSA_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_get_ECDSA_method
%xdefine __objectivepgp_ENGINE_get_RSA_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_get_RSA_method
%xdefine __objectivepgp_ENGINE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_new
%xdefine __objectivepgp_ENGINE_set_ECDSA_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_set_ECDSA_method
%xdefine __objectivepgp_ENGINE_set_RSA_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_set_RSA_method
%xdefine __objectivepgp_METHOD_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_METHOD_ref
%xdefine __objectivepgp_METHOD_unref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_METHOD_unref
%xdefine __objectivepgp_EVP_DigestSign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSign
%xdefine __objectivepgp_EVP_DigestSignFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignFinal
%xdefine __objectivepgp_EVP_DigestSignInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignInit
%xdefine __objectivepgp_EVP_DigestSignUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignUpdate
%xdefine __objectivepgp_EVP_DigestVerify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerify
%xdefine __objectivepgp_EVP_DigestVerifyFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyFinal
%xdefine __objectivepgp_EVP_DigestVerifyInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyInit
%xdefine __objectivepgp_EVP_DigestVerifyUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyUpdate
%xdefine __objectivepgp_EVP_PKEY_CTX_get_signature_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_signature_md
%xdefine __objectivepgp_EVP_PKEY_CTX_set_signature_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_signature_md
%xdefine __objectivepgp_EVP_PKEY_assign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign
%xdefine __objectivepgp_EVP_PKEY_assign_DSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_DSA
%xdefine __objectivepgp_EVP_PKEY_assign_EC_KEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_EC_KEY
%xdefine __objectivepgp_EVP_PKEY_assign_RSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_RSA
%xdefine __objectivepgp_EVP_PKEY_base_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_base_id
%xdefine __objectivepgp_EVP_PKEY_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_bits
%xdefine __objectivepgp_EVP_PKEY_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_cmp
%xdefine __objectivepgp_EVP_PKEY_cmp_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_cmp_parameters
%xdefine __objectivepgp_EVP_PKEY_copy_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_copy_parameters
%xdefine __objectivepgp_EVP_PKEY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_free
%xdefine __objectivepgp_EVP_PKEY_get0_DH _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_DH
%xdefine __objectivepgp_EVP_PKEY_get0_DSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_DSA
%xdefine __objectivepgp_EVP_PKEY_get0_EC_KEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_EC_KEY
%xdefine __objectivepgp_EVP_PKEY_get0_RSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_RSA
%xdefine __objectivepgp_EVP_PKEY_get1_DH _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_DH
%xdefine __objectivepgp_EVP_PKEY_get1_DSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_DSA
%xdefine __objectivepgp_EVP_PKEY_get1_EC_KEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_EC_KEY
%xdefine __objectivepgp_EVP_PKEY_get1_RSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_RSA
%xdefine __objectivepgp_EVP_PKEY_get_raw_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get_raw_private_key
%xdefine __objectivepgp_EVP_PKEY_get_raw_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get_raw_public_key
%xdefine __objectivepgp_EVP_PKEY_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_id
%xdefine __objectivepgp_EVP_PKEY_is_opaque _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_is_opaque
%xdefine __objectivepgp_EVP_PKEY_missing_parameters _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_missing_parameters
%xdefine __objectivepgp_EVP_PKEY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new
%xdefine __objectivepgp_EVP_PKEY_new_raw_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new_raw_private_key
%xdefine __objectivepgp_EVP_PKEY_new_raw_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new_raw_public_key
%xdefine __objectivepgp_EVP_PKEY_set1_DSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_DSA
%xdefine __objectivepgp_EVP_PKEY_set1_EC_KEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_EC_KEY
%xdefine __objectivepgp_EVP_PKEY_set1_RSA _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_RSA
%xdefine __objectivepgp_EVP_PKEY_set_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set_type
%xdefine __objectivepgp_EVP_PKEY_size _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_size
%xdefine __objectivepgp_EVP_PKEY_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_type
%xdefine __objectivepgp_EVP_PKEY_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_up_ref
%xdefine __objectivepgp_EVP_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_cleanup
%xdefine __objectivepgp_OPENSSL_add_all_algorithms_conf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_add_all_algorithms_conf
%xdefine __objectivepgp_OpenSSL_add_all_algorithms _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_algorithms
%xdefine __objectivepgp_OpenSSL_add_all_ciphers _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_ciphers
%xdefine __objectivepgp_OpenSSL_add_all_digests _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_digests
%xdefine __objectivepgp_EVP_marshal_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_private_key
%xdefine __objectivepgp_EVP_marshal_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_public_key
%xdefine __objectivepgp_EVP_parse_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_private_key
%xdefine __objectivepgp_EVP_parse_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_public_key
%xdefine __objectivepgp_d2i_AutoPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_AutoPrivateKey
%xdefine __objectivepgp_d2i_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey
%xdefine __objectivepgp_d2i_PublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PublicKey
%xdefine __objectivepgp_i2d_PublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PublicKey
%xdefine __objectivepgp_EVP_PKEY_CTX_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_ctrl
%xdefine __objectivepgp_EVP_PKEY_CTX_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_dup
%xdefine __objectivepgp_EVP_PKEY_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_free
%xdefine __objectivepgp_EVP_PKEY_CTX_get0_pkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get0_pkey
%xdefine __objectivepgp_EVP_PKEY_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_new
%xdefine __objectivepgp_EVP_PKEY_CTX_new_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_new_id
%xdefine __objectivepgp_EVP_PKEY_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_decrypt
%xdefine __objectivepgp_EVP_PKEY_decrypt_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_decrypt_init
%xdefine __objectivepgp_EVP_PKEY_derive _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive
%xdefine __objectivepgp_EVP_PKEY_derive_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive_init
%xdefine __objectivepgp_EVP_PKEY_derive_set_peer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive_set_peer
%xdefine __objectivepgp_EVP_PKEY_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_encrypt
%xdefine __objectivepgp_EVP_PKEY_encrypt_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_encrypt_init
%xdefine __objectivepgp_EVP_PKEY_keygen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_keygen
%xdefine __objectivepgp_EVP_PKEY_keygen_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_keygen_init
%xdefine __objectivepgp_EVP_PKEY_paramgen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_paramgen
%xdefine __objectivepgp_EVP_PKEY_paramgen_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_paramgen_init
%xdefine __objectivepgp_EVP_PKEY_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_sign
%xdefine __objectivepgp_EVP_PKEY_sign_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_sign_init
%xdefine __objectivepgp_EVP_PKEY_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify
%xdefine __objectivepgp_EVP_PKEY_verify_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_init
%xdefine __objectivepgp_EVP_PKEY_verify_recover _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_recover
%xdefine __objectivepgp_EVP_PKEY_verify_recover_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_recover_init
%xdefine __objectivepgp_dsa_asn1_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_dsa_asn1_meth
%xdefine __objectivepgp_EVP_PKEY_CTX_set_ec_param_enc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_ec_param_enc
%xdefine __objectivepgp_EVP_PKEY_CTX_set_ec_paramgen_curve_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_ec_paramgen_curve_nid
%xdefine __objectivepgp_ec_pkey_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_pkey_meth
%xdefine __objectivepgp_ec_asn1_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ec_asn1_meth
%xdefine __objectivepgp_ed25519_pkey_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ed25519_pkey_meth
%xdefine __objectivepgp_ed25519_asn1_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ed25519_asn1_meth
%xdefine __objectivepgp_EVP_PKEY_CTX_get0_rsa_oaep_label _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get0_rsa_oaep_label
%xdefine __objectivepgp_EVP_PKEY_CTX_get_rsa_mgf1_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_mgf1_md
%xdefine __objectivepgp_EVP_PKEY_CTX_get_rsa_oaep_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_oaep_md
%xdefine __objectivepgp_EVP_PKEY_CTX_get_rsa_padding _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_padding
%xdefine __objectivepgp_EVP_PKEY_CTX_get_rsa_pss_saltlen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_pss_saltlen
%xdefine __objectivepgp_EVP_PKEY_CTX_set0_rsa_oaep_label _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set0_rsa_oaep_label
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_bits _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_bits
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_pubexp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_pubexp
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_mgf1_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_mgf1_md
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_oaep_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_oaep_md
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_padding _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_padding
%xdefine __objectivepgp_EVP_PKEY_CTX_set_rsa_pss_saltlen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_pss_saltlen
%xdefine __objectivepgp_rsa_pkey_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_pkey_meth
%xdefine __objectivepgp_rsa_asn1_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rsa_asn1_meth
%xdefine __objectivepgp_x25519_pkey_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_pkey_meth
%xdefine __objectivepgp_EVP_PKEY_get1_tls_encodedpoint _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_tls_encodedpoint
%xdefine __objectivepgp_EVP_PKEY_set1_tls_encodedpoint _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_tls_encodedpoint
%xdefine __objectivepgp_x25519_asn1_meth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_asn1_meth
%xdefine __objectivepgp_PKCS5_PBKDF2_HMAC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_PBKDF2_HMAC
%xdefine __objectivepgp_PKCS5_PBKDF2_HMAC_SHA1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_PBKDF2_HMAC_SHA1
%xdefine __objectivepgp_EVP_PKEY_print_params _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_params
%xdefine __objectivepgp_EVP_PKEY_print_private _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_private
%xdefine __objectivepgp_EVP_PKEY_print_public _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_public
%xdefine __objectivepgp_EVP_PBE_scrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PBE_scrypt
%xdefine __objectivepgp_EVP_SignFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignFinal
%xdefine __objectivepgp_EVP_SignInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignInit
%xdefine __objectivepgp_EVP_SignInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignInit_ex
%xdefine __objectivepgp_EVP_SignUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignUpdate
%xdefine __objectivepgp_EVP_VerifyFinal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyFinal
%xdefine __objectivepgp_EVP_VerifyInit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyInit
%xdefine __objectivepgp_EVP_VerifyInit_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyInit_ex
%xdefine __objectivepgp_EVP_VerifyUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyUpdate
%xdefine __objectivepgp_CRYPTO_cleanup_all_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cleanup_all_ex_data
%xdefine __objectivepgp_CRYPTO_free_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_free_ex_data
%xdefine __objectivepgp_CRYPTO_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_ex_data
%xdefine __objectivepgp_CRYPTO_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_ex_new_index
%xdefine __objectivepgp_CRYPTO_new_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_new_ex_data
%xdefine __objectivepgp_CRYPTO_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_ex_data
%xdefine __objectivepgp_HKDF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HKDF
%xdefine __objectivepgp_HKDF_expand _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HKDF_expand
%xdefine __objectivepgp_HKDF_extract _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HKDF_extract
%xdefine __objectivepgp_HRSS_decap _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_decap
%xdefine __objectivepgp_HRSS_encap _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_encap
%xdefine __objectivepgp_HRSS_generate_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_generate_key
%xdefine __objectivepgp_HRSS_marshal_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_marshal_public_key
%xdefine __objectivepgp_HRSS_parse_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_parse_public_key
%xdefine __objectivepgp_HRSS_poly2_rotr_consttime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly2_rotr_consttime
%xdefine __objectivepgp_HRSS_poly3_invert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly3_invert
%xdefine __objectivepgp_HRSS_poly3_mul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly3_mul
%xdefine __objectivepgp_lh_delete _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_delete
%xdefine __objectivepgp_lh_doall_arg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_doall_arg
%xdefine __objectivepgp_lh_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_free
%xdefine __objectivepgp_lh_insert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_insert
%xdefine __objectivepgp_lh_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_new
%xdefine __objectivepgp_lh_num_items _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_num_items
%xdefine __objectivepgp_lh_retrieve _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_retrieve
%xdefine __objectivepgp_lh_retrieve_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_retrieve_key
%xdefine __objectivepgp_lh_strhash _ %+ BORINGSSL_PREFIX %+ __objectivepgp_lh_strhash
%xdefine __objectivepgp_BIO_snprintf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_snprintf
%xdefine __objectivepgp_BIO_vsnprintf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BIO_vsnprintf
%xdefine __objectivepgp_CRYPTO_memcmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_memcmp
%xdefine __objectivepgp_OPENSSL_cleanse _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cleanse
%xdefine __objectivepgp_OPENSSL_clear_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_clear_free
%xdefine __objectivepgp_OPENSSL_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_free
%xdefine __objectivepgp_OPENSSL_hash32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_hash32
%xdefine __objectivepgp_OPENSSL_malloc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_malloc
%xdefine __objectivepgp_OPENSSL_realloc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_realloc
%xdefine __objectivepgp_OPENSSL_strcasecmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strcasecmp
%xdefine __objectivepgp_OPENSSL_strdup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strdup
%xdefine __objectivepgp_OPENSSL_strncasecmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strncasecmp
%xdefine __objectivepgp_OPENSSL_strnlen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strnlen
%xdefine __objectivepgp_OPENSSL_tolower _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_tolower
%xdefine __objectivepgp_sdallocx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sdallocx
%xdefine __objectivepgp_OBJ_cbs2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cbs2nid
%xdefine __objectivepgp_OBJ_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cleanup
%xdefine __objectivepgp_OBJ_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cmp
%xdefine __objectivepgp_OBJ_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_create
%xdefine __objectivepgp_OBJ_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_dup
%xdefine __objectivepgp_OBJ_get0_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_get0_data
%xdefine __objectivepgp_OBJ_length _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_length
%xdefine __objectivepgp_OBJ_ln2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_ln2nid
%xdefine __objectivepgp_OBJ_nid2cbb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2cbb
%xdefine __objectivepgp_OBJ_nid2ln _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2ln
%xdefine __objectivepgp_OBJ_nid2obj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2obj
%xdefine __objectivepgp_OBJ_nid2sn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2sn
%xdefine __objectivepgp_OBJ_obj2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_obj2nid
%xdefine __objectivepgp_OBJ_obj2txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_obj2txt
%xdefine __objectivepgp_OBJ_sn2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_sn2nid
%xdefine __objectivepgp_OBJ_txt2nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_txt2nid
%xdefine __objectivepgp_OBJ_txt2obj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_txt2obj
%xdefine __objectivepgp_OBJ_find_sigid_algs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_find_sigid_algs
%xdefine __objectivepgp_OBJ_find_sigid_by_algs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OBJ_find_sigid_by_algs
%xdefine __objectivepgp_PEM_read_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSAPrivateKey
%xdefine __objectivepgp_PEM_read_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSA_PUBKEY
%xdefine __objectivepgp_PEM_read_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSAparams
%xdefine __objectivepgp_PEM_read_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_ECPrivateKey
%xdefine __objectivepgp_PEM_read_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_EC_PUBKEY
%xdefine __objectivepgp_PEM_read_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS7
%xdefine __objectivepgp_PEM_read_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PUBKEY
%xdefine __objectivepgp_PEM_read_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSAPrivateKey
%xdefine __objectivepgp_PEM_read_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSAPublicKey
%xdefine __objectivepgp_PEM_read_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSA_PUBKEY
%xdefine __objectivepgp_PEM_read_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_CRL
%xdefine __objectivepgp_PEM_read_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_REQ
%xdefine __objectivepgp_PEM_read_bio_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSAPrivateKey
%xdefine __objectivepgp_PEM_read_bio_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSA_PUBKEY
%xdefine __objectivepgp_PEM_read_bio_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSAparams
%xdefine __objectivepgp_PEM_read_bio_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_ECPrivateKey
%xdefine __objectivepgp_PEM_read_bio_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_EC_PUBKEY
%xdefine __objectivepgp_PEM_read_bio_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS7
%xdefine __objectivepgp_PEM_read_bio_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PUBKEY
%xdefine __objectivepgp_PEM_read_bio_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSAPrivateKey
%xdefine __objectivepgp_PEM_read_bio_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSAPublicKey
%xdefine __objectivepgp_PEM_read_bio_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSA_PUBKEY
%xdefine __objectivepgp_PEM_read_bio_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_CRL
%xdefine __objectivepgp_PEM_read_bio_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_REQ
%xdefine __objectivepgp_PEM_write_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DHparams
%xdefine __objectivepgp_PEM_write_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSAPrivateKey
%xdefine __objectivepgp_PEM_write_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSA_PUBKEY
%xdefine __objectivepgp_PEM_write_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSAparams
%xdefine __objectivepgp_PEM_write_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_ECPrivateKey
%xdefine __objectivepgp_PEM_write_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_EC_PUBKEY
%xdefine __objectivepgp_PEM_write_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS7
%xdefine __objectivepgp_PEM_write_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PUBKEY
%xdefine __objectivepgp_PEM_write_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSAPrivateKey
%xdefine __objectivepgp_PEM_write_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSAPublicKey
%xdefine __objectivepgp_PEM_write_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSA_PUBKEY
%xdefine __objectivepgp_PEM_write_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_CRL
%xdefine __objectivepgp_PEM_write_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_REQ
%xdefine __objectivepgp_PEM_write_X509_REQ_NEW _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_REQ_NEW
%xdefine __objectivepgp_PEM_write_bio_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DHparams
%xdefine __objectivepgp_PEM_write_bio_DSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSAPrivateKey
%xdefine __objectivepgp_PEM_write_bio_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSA_PUBKEY
%xdefine __objectivepgp_PEM_write_bio_DSAparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSAparams
%xdefine __objectivepgp_PEM_write_bio_ECPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_ECPrivateKey
%xdefine __objectivepgp_PEM_write_bio_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_EC_PUBKEY
%xdefine __objectivepgp_PEM_write_bio_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS7
%xdefine __objectivepgp_PEM_write_bio_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PUBKEY
%xdefine __objectivepgp_PEM_write_bio_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSAPrivateKey
%xdefine __objectivepgp_PEM_write_bio_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSAPublicKey
%xdefine __objectivepgp_PEM_write_bio_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSA_PUBKEY
%xdefine __objectivepgp_PEM_write_bio_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_CRL
%xdefine __objectivepgp_PEM_write_bio_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_REQ
%xdefine __objectivepgp_PEM_write_bio_X509_REQ_NEW _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_REQ_NEW
%xdefine __objectivepgp_PEM_X509_INFO_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_read
%xdefine __objectivepgp_PEM_X509_INFO_read_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_read_bio
%xdefine __objectivepgp_PEM_X509_INFO_write_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_write_bio
%xdefine __objectivepgp_PEM_ASN1_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_read
%xdefine __objectivepgp_PEM_ASN1_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_write
%xdefine __objectivepgp_PEM_ASN1_write_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_write_bio
%xdefine __objectivepgp_PEM_bytes_read_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_bytes_read_bio
%xdefine __objectivepgp_PEM_def_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_def_callback
%xdefine __objectivepgp_PEM_dek_info _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_dek_info
%xdefine __objectivepgp_PEM_do_header _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_do_header
%xdefine __objectivepgp_PEM_get_EVP_CIPHER_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_get_EVP_CIPHER_INFO
%xdefine __objectivepgp_PEM_proc_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_proc_type
%xdefine __objectivepgp_PEM_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read
%xdefine __objectivepgp_PEM_read_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio
%xdefine __objectivepgp_PEM_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write
%xdefine __objectivepgp_PEM_write_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio
%xdefine __objectivepgp_PEM_ASN1_read_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_read_bio
%xdefine __objectivepgp_PEM_read_PKCS8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS8
%xdefine __objectivepgp_PEM_read_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_PEM_read_bio_PKCS8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS8
%xdefine __objectivepgp_PEM_read_bio_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_PEM_write_PKCS8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8
%xdefine __objectivepgp_PEM_write_PKCS8PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8PrivateKey
%xdefine __objectivepgp_PEM_write_PKCS8PrivateKey_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8PrivateKey_nid
%xdefine __objectivepgp_PEM_write_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_PEM_write_bio_PKCS8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8
%xdefine __objectivepgp_PEM_write_bio_PKCS8PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8PrivateKey
%xdefine __objectivepgp_PEM_write_bio_PKCS8PrivateKey_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8PrivateKey_nid
%xdefine __objectivepgp_PEM_write_bio_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_d2i_PKCS8PrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8PrivateKey_bio
%xdefine __objectivepgp_d2i_PKCS8PrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8PrivateKey_fp
%xdefine __objectivepgp_i2d_PKCS8PrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_bio
%xdefine __objectivepgp_i2d_PKCS8PrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_fp
%xdefine __objectivepgp_i2d_PKCS8PrivateKey_nid_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_nid_bio
%xdefine __objectivepgp_i2d_PKCS8PrivateKey_nid_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_nid_fp
%xdefine __objectivepgp_PEM_read_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DHparams
%xdefine __objectivepgp_PEM_read_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PrivateKey
%xdefine __objectivepgp_PEM_read_bio_DHparams _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DHparams
%xdefine __objectivepgp_PEM_read_bio_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PrivateKey
%xdefine __objectivepgp_PEM_write_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PrivateKey
%xdefine __objectivepgp_PEM_write_bio_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PrivateKey
%xdefine __objectivepgp_PEM_read_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509
%xdefine __objectivepgp_PEM_read_bio_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509
%xdefine __objectivepgp_PEM_write_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509
%xdefine __objectivepgp_PEM_write_bio_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509
%xdefine __objectivepgp_PEM_read_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_AUX
%xdefine __objectivepgp_PEM_read_bio_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_AUX
%xdefine __objectivepgp_PEM_write_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_AUX
%xdefine __objectivepgp_PEM_write_bio_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_AUX
%xdefine __objectivepgp_PKCS7_get_raw_certificates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_raw_certificates
%xdefine __objectivepgp_pkcs7_bundle _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs7_bundle
%xdefine __objectivepgp_pkcs7_parse_header _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs7_parse_header
%xdefine __objectivepgp_PKCS7_bundle_CRLs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_bundle_CRLs
%xdefine __objectivepgp_PKCS7_bundle_certificates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_bundle_certificates
%xdefine __objectivepgp_PKCS7_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_free
%xdefine __objectivepgp_PKCS7_get_CRLs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_CRLs
%xdefine __objectivepgp_PKCS7_get_PEM_CRLs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_PEM_CRLs
%xdefine __objectivepgp_PKCS7_get_PEM_certificates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_PEM_certificates
%xdefine __objectivepgp_PKCS7_get_certificates _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_certificates
%xdefine __objectivepgp_PKCS7_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_sign
%xdefine __objectivepgp_PKCS7_type_is_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_data
%xdefine __objectivepgp_PKCS7_type_is_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_digest
%xdefine __objectivepgp_PKCS7_type_is_encrypted _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_encrypted
%xdefine __objectivepgp_PKCS7_type_is_enveloped _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_enveloped
%xdefine __objectivepgp_PKCS7_type_is_signed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_signed
%xdefine __objectivepgp_PKCS7_type_is_signedAndEnveloped _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_signedAndEnveloped
%xdefine __objectivepgp_d2i_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS7
%xdefine __objectivepgp_d2i_PKCS7_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS7_bio
%xdefine __objectivepgp_i2d_PKCS7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS7
%xdefine __objectivepgp_i2d_PKCS7_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS7_bio
%xdefine __objectivepgp_PKCS8_marshal_encrypted_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_marshal_encrypted_private_key
%xdefine __objectivepgp_PKCS8_parse_encrypted_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_parse_encrypted_private_key
%xdefine __objectivepgp_pkcs12_key_gen _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_key_gen
%xdefine __objectivepgp_pkcs12_pbe_encrypt_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_pbe_encrypt_init
%xdefine __objectivepgp_pkcs8_pbe_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs8_pbe_decrypt
%xdefine __objectivepgp_EVP_PKCS82PKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKCS82PKEY
%xdefine __objectivepgp_EVP_PKEY2PKCS8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY2PKCS8
%xdefine __objectivepgp_PKCS12_PBE_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_PBE_add
%xdefine __objectivepgp_PKCS12_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_create
%xdefine __objectivepgp_PKCS12_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_free
%xdefine __objectivepgp_PKCS12_get_key_and_certs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_get_key_and_certs
%xdefine __objectivepgp_PKCS12_parse _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_parse
%xdefine __objectivepgp_PKCS12_verify_mac _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_verify_mac
%xdefine __objectivepgp_PKCS8_PRIV_KEY_INFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_free
%xdefine __objectivepgp_PKCS8_PRIV_KEY_INFO_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_it
%xdefine __objectivepgp_PKCS8_PRIV_KEY_INFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_new
%xdefine __objectivepgp_PKCS8_decrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_decrypt
%xdefine __objectivepgp_PKCS8_encrypt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_encrypt
%xdefine __objectivepgp_d2i_PKCS12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12
%xdefine __objectivepgp_d2i_PKCS12_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12_bio
%xdefine __objectivepgp_d2i_PKCS12_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12_fp
%xdefine __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_i2d_PKCS12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12
%xdefine __objectivepgp_i2d_PKCS12_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12_bio
%xdefine __objectivepgp_i2d_PKCS12_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12_fp
%xdefine __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO
%xdefine __objectivepgp_pkcs12_iterations_acceptable _ %+ BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_iterations_acceptable
%xdefine __objectivepgp_PKCS5_pbe2_decrypt_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_pbe2_decrypt_init
%xdefine __objectivepgp_PKCS5_pbe2_encrypt_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_pbe2_encrypt_init
%xdefine __objectivepgp_CRYPTO_poly1305_finish _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_finish
%xdefine __objectivepgp_CRYPTO_poly1305_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_init
%xdefine __objectivepgp_CRYPTO_poly1305_update _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_update
%xdefine __objectivepgp_CRYPTO_BUFFER_POOL_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_POOL_free
%xdefine __objectivepgp_CRYPTO_BUFFER_POOL_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_POOL_new
%xdefine __objectivepgp_CRYPTO_BUFFER_alloc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_alloc
%xdefine __objectivepgp_CRYPTO_BUFFER_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_data
%xdefine __objectivepgp_CRYPTO_BUFFER_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_free
%xdefine __objectivepgp_CRYPTO_BUFFER_init_CBS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_init_CBS
%xdefine __objectivepgp_CRYPTO_BUFFER_len _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_len
%xdefine __objectivepgp_CRYPTO_BUFFER_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_new
%xdefine __objectivepgp_CRYPTO_BUFFER_new_from_CBS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_new_from_CBS
%xdefine __objectivepgp_CRYPTO_BUFFER_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_up_ref
%xdefine __objectivepgp_RAND_enable_fork_unsafe_buffering _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_enable_fork_unsafe_buffering
%xdefine __objectivepgp_rand_fork_unsafe_buffering_enabled _ %+ BORINGSSL_PREFIX %+ __objectivepgp_rand_fork_unsafe_buffering_enabled
%xdefine __objectivepgp_RAND_SSLeay _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_SSLeay
%xdefine __objectivepgp_RAND_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_add
%xdefine __objectivepgp_RAND_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_cleanup
%xdefine __objectivepgp_RAND_egd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_egd
%xdefine __objectivepgp_RAND_file_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_file_name
%xdefine __objectivepgp_RAND_get_rand_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_get_rand_method
%xdefine __objectivepgp_RAND_load_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_load_file
%xdefine __objectivepgp_RAND_poll _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_poll
%xdefine __objectivepgp_RAND_seed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_seed
%xdefine __objectivepgp_RAND_set_rand_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_set_rand_method
%xdefine __objectivepgp_RAND_status _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RAND_status
%xdefine __objectivepgp_RC4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RC4
%xdefine __objectivepgp_RC4_set_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RC4_set_key
%xdefine __objectivepgp_CRYPTO_refcount_dec_and_test_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_refcount_dec_and_test_zero
%xdefine __objectivepgp_CRYPTO_refcount_inc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_refcount_inc
%xdefine __objectivepgp_RSAPrivateKey_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSAPrivateKey_dup
%xdefine __objectivepgp_RSAPublicKey_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSAPublicKey_dup
%xdefine __objectivepgp_RSA_marshal_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_marshal_private_key
%xdefine __objectivepgp_RSA_marshal_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_marshal_public_key
%xdefine __objectivepgp_RSA_parse_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_parse_private_key
%xdefine __objectivepgp_RSA_parse_public_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_parse_public_key
%xdefine __objectivepgp_RSA_private_key_from_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_key_from_bytes
%xdefine __objectivepgp_RSA_private_key_to_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_key_to_bytes
%xdefine __objectivepgp_RSA_public_key_from_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_key_from_bytes
%xdefine __objectivepgp_RSA_public_key_to_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_key_to_bytes
%xdefine __objectivepgp_d2i_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey
%xdefine __objectivepgp_d2i_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey
%xdefine __objectivepgp_i2d_RSAPrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey
%xdefine __objectivepgp_i2d_RSAPublicKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey
%xdefine __objectivepgp_RSA_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_print
%xdefine __objectivepgp_sk_deep_copy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_deep_copy
%xdefine __objectivepgp_sk_delete _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_delete
%xdefine __objectivepgp_sk_delete_ptr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_delete_ptr
%xdefine __objectivepgp_sk_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_dup
%xdefine __objectivepgp_sk_find _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_find
%xdefine __objectivepgp_sk_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_free
%xdefine __objectivepgp_sk_insert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_insert
%xdefine __objectivepgp_sk_is_sorted _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_is_sorted
%xdefine __objectivepgp_sk_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_new
%xdefine __objectivepgp_sk_new_null _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_new_null
%xdefine __objectivepgp_sk_num _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_num
%xdefine __objectivepgp_sk_pop _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_pop
%xdefine __objectivepgp_sk_pop_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_pop_free
%xdefine __objectivepgp_sk_pop_free_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_pop_free_ex
%xdefine __objectivepgp_sk_push _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_push
%xdefine __objectivepgp_sk_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_set
%xdefine __objectivepgp_sk_set_cmp_func _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_set_cmp_func
%xdefine __objectivepgp_sk_shift _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_shift
%xdefine __objectivepgp_sk_sort _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_sort
%xdefine __objectivepgp_sk_value _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_value
%xdefine __objectivepgp_sk_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sk_zero
%xdefine __objectivepgp_SIPHASH_24 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SIPHASH_24
%xdefine __objectivepgp_CRYPTO_THREADID_current _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_current
%xdefine __objectivepgp_CRYPTO_THREADID_set_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_callback
%xdefine __objectivepgp_CRYPTO_THREADID_set_numeric _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_numeric
%xdefine __objectivepgp_CRYPTO_THREADID_set_pointer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_pointer
%xdefine __objectivepgp_CRYPTO_get_dynlock_create_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_create_callback
%xdefine __objectivepgp_CRYPTO_get_dynlock_destroy_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_destroy_callback
%xdefine __objectivepgp_CRYPTO_get_dynlock_lock_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_lock_callback
%xdefine __objectivepgp_CRYPTO_get_lock_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_lock_name
%xdefine __objectivepgp_CRYPTO_get_locking_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_locking_callback
%xdefine __objectivepgp_CRYPTO_num_locks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_num_locks
%xdefine __objectivepgp_CRYPTO_set_add_lock_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_add_lock_callback
%xdefine __objectivepgp_CRYPTO_set_dynlock_create_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_create_callback
%xdefine __objectivepgp_CRYPTO_set_dynlock_destroy_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_destroy_callback
%xdefine __objectivepgp_CRYPTO_set_dynlock_lock_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_lock_callback
%xdefine __objectivepgp_CRYPTO_set_id_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_id_callback
%xdefine __objectivepgp_CRYPTO_set_locking_callback _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_locking_callback
%xdefine __objectivepgp_CRYPTO_MUTEX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_cleanup
%xdefine __objectivepgp_CRYPTO_MUTEX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_init
%xdefine __objectivepgp_CRYPTO_MUTEX_lock_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_lock_read
%xdefine __objectivepgp_CRYPTO_MUTEX_lock_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_lock_write
%xdefine __objectivepgp_CRYPTO_MUTEX_unlock_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_unlock_read
%xdefine __objectivepgp_CRYPTO_MUTEX_unlock_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_unlock_write
%xdefine __objectivepgp_CRYPTO_STATIC_MUTEX_lock_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_lock_read
%xdefine __objectivepgp_CRYPTO_STATIC_MUTEX_lock_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_lock_write
%xdefine __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_read _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_read
%xdefine __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_write _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_write
%xdefine __objectivepgp_CRYPTO_get_thread_local _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_thread_local
%xdefine __objectivepgp_CRYPTO_once _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_once
%xdefine __objectivepgp_CRYPTO_set_thread_local _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_thread_local
%xdefine __objectivepgp_ASN1_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_digest
%xdefine __objectivepgp_ASN1_item_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_digest
%xdefine __objectivepgp_ASN1_item_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_sign
%xdefine __objectivepgp_ASN1_item_sign_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_sign_ctx
%xdefine __objectivepgp_ASN1_STRING_print_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print_ex
%xdefine __objectivepgp_ASN1_STRING_print_ex_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print_ex_fp
%xdefine __objectivepgp_ASN1_STRING_to_UTF8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_to_UTF8
%xdefine __objectivepgp_X509_NAME_print_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print_ex
%xdefine __objectivepgp_X509_NAME_print_ex_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print_ex_fp
%xdefine __objectivepgp_ASN1_item_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_verify
%xdefine __objectivepgp_x509_digest_sign_algorithm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509_digest_sign_algorithm
%xdefine __objectivepgp_x509_digest_verify_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509_digest_verify_init
%xdefine __objectivepgp_ASN1_generate_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_generate_nconf
%xdefine __objectivepgp_ASN1_generate_v3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_generate_v3
%xdefine __objectivepgp_X509_LOOKUP_hash_dir _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_hash_dir
%xdefine __objectivepgp_X509_LOOKUP_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_file
%xdefine __objectivepgp_X509_load_cert_crl_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_load_cert_crl_file
%xdefine __objectivepgp_X509_load_cert_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_load_cert_file
%xdefine __objectivepgp_X509_load_crl_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_load_crl_file
%xdefine __objectivepgp_i2d_PrivateKey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey
%xdefine __objectivepgp_RSA_PSS_PARAMS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_free
%xdefine __objectivepgp_RSA_PSS_PARAMS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_it
%xdefine __objectivepgp_RSA_PSS_PARAMS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_new
%xdefine __objectivepgp_d2i_RSA_PSS_PARAMS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PSS_PARAMS
%xdefine __objectivepgp_i2d_RSA_PSS_PARAMS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PSS_PARAMS
%xdefine __objectivepgp_x509_print_rsa_pss_params _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509_print_rsa_pss_params
%xdefine __objectivepgp_x509_rsa_ctx_to_pss _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509_rsa_ctx_to_pss
%xdefine __objectivepgp_x509_rsa_pss_to_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509_rsa_pss_to_ctx
%xdefine __objectivepgp_X509_CRL_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_print
%xdefine __objectivepgp_X509_CRL_print_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_print_fp
%xdefine __objectivepgp_X509_REQ_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print
%xdefine __objectivepgp_X509_REQ_print_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print_ex
%xdefine __objectivepgp_X509_REQ_print_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print_fp
%xdefine __objectivepgp_ASN1_GENERALIZEDTIME_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_print
%xdefine __objectivepgp_ASN1_STRING_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print
%xdefine __objectivepgp_ASN1_TIME_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_print
%xdefine __objectivepgp_ASN1_UTCTIME_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_print
%xdefine __objectivepgp_X509_NAME_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print
%xdefine __objectivepgp_X509_ocspid_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ocspid_print
%xdefine __objectivepgp_X509_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_print
%xdefine __objectivepgp_X509_print_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_print_ex
%xdefine __objectivepgp_X509_print_ex_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_print_ex_fp
%xdefine __objectivepgp_X509_print_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_print_fp
%xdefine __objectivepgp_X509_signature_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_signature_print
%xdefine __objectivepgp_X509_CERT_AUX_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_print
%xdefine __objectivepgp_PKCS8_pkey_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_pkey_get0
%xdefine __objectivepgp_PKCS8_pkey_set0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_pkey_set0
%xdefine __objectivepgp_X509_signature_dump _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_signature_dump
%xdefine __objectivepgp_X509_ATTRIBUTE_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_count
%xdefine __objectivepgp_X509_ATTRIBUTE_create_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_NID
%xdefine __objectivepgp_X509_ATTRIBUTE_create_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_OBJ
%xdefine __objectivepgp_X509_ATTRIBUTE_create_by_txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_txt
%xdefine __objectivepgp_X509_ATTRIBUTE_get0_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_data
%xdefine __objectivepgp_X509_ATTRIBUTE_get0_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_object
%xdefine __objectivepgp_X509_ATTRIBUTE_get0_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_type
%xdefine __objectivepgp_X509_ATTRIBUTE_set1_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_set1_data
%xdefine __objectivepgp_X509_ATTRIBUTE_set1_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_set1_object
%xdefine __objectivepgp_X509at_add1_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr
%xdefine __objectivepgp_X509at_add1_attr_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_NID
%xdefine __objectivepgp_X509at_add1_attr_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_OBJ
%xdefine __objectivepgp_X509at_add1_attr_by_txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_txt
%xdefine __objectivepgp_X509at_delete_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_delete_attr
%xdefine __objectivepgp_X509at_get0_data_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get0_data_by_OBJ
%xdefine __objectivepgp_X509at_get_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr
%xdefine __objectivepgp_X509at_get_attr_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_by_NID
%xdefine __objectivepgp_X509at_get_attr_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_by_OBJ
%xdefine __objectivepgp_X509at_get_attr_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_count
%xdefine __objectivepgp_X509_CRL_check_suiteb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_check_suiteb
%xdefine __objectivepgp_X509_CRL_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_cmp
%xdefine __objectivepgp_X509_CRL_match _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_match
%xdefine __objectivepgp_X509_NAME_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_cmp
%xdefine __objectivepgp_X509_NAME_hash _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_hash
%xdefine __objectivepgp_X509_NAME_hash_old _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_hash_old
%xdefine __objectivepgp_X509_chain_check_suiteb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_chain_check_suiteb
%xdefine __objectivepgp_X509_chain_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_chain_up_ref
%xdefine __objectivepgp_X509_check_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_private_key
%xdefine __objectivepgp_X509_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp
%xdefine __objectivepgp_X509_find_by_issuer_and_serial _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_find_by_issuer_and_serial
%xdefine __objectivepgp_X509_find_by_subject _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_find_by_subject
%xdefine __objectivepgp_X509_get0_pubkey_bitstr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_pubkey_bitstr
%xdefine __objectivepgp_X509_get_issuer_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_issuer_name
%xdefine __objectivepgp_X509_get_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_pubkey
%xdefine __objectivepgp_X509_get_serialNumber _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_serialNumber
%xdefine __objectivepgp_X509_get_subject_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_subject_name
%xdefine __objectivepgp_X509_issuer_and_serial_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_and_serial_cmp
%xdefine __objectivepgp_X509_issuer_and_serial_hash _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_and_serial_hash
%xdefine __objectivepgp_X509_issuer_name_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_cmp
%xdefine __objectivepgp_X509_issuer_name_hash _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_hash
%xdefine __objectivepgp_X509_issuer_name_hash_old _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_hash_old
%xdefine __objectivepgp_X509_subject_name_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_cmp
%xdefine __objectivepgp_X509_subject_name_hash _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_hash
%xdefine __objectivepgp_X509_subject_name_hash_old _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_hash_old
%xdefine __objectivepgp_X509_STORE_load_locations _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_load_locations
%xdefine __objectivepgp_X509_STORE_set_default_paths _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_default_paths
%xdefine __objectivepgp_X509_get_default_cert_area _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_area
%xdefine __objectivepgp_X509_get_default_cert_dir _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_dir
%xdefine __objectivepgp_X509_get_default_cert_dir_env _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_dir_env
%xdefine __objectivepgp_X509_get_default_cert_file _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_file
%xdefine __objectivepgp_X509_get_default_cert_file_env _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_file_env
%xdefine __objectivepgp_X509_get_default_private_dir _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_private_dir
%xdefine __objectivepgp_X509_CRL_add1_ext_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add1_ext_i2d
%xdefine __objectivepgp_X509_CRL_add_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add_ext
%xdefine __objectivepgp_X509_CRL_delete_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_delete_ext
%xdefine __objectivepgp_X509_CRL_get_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext
%xdefine __objectivepgp_X509_CRL_get_ext_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_NID
%xdefine __objectivepgp_X509_CRL_get_ext_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_OBJ
%xdefine __objectivepgp_X509_CRL_get_ext_by_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_critical
%xdefine __objectivepgp_X509_CRL_get_ext_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_count
%xdefine __objectivepgp_X509_CRL_get_ext_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_d2i
%xdefine __objectivepgp_X509_REVOKED_add1_ext_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_add1_ext_i2d
%xdefine __objectivepgp_X509_REVOKED_add_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_add_ext
%xdefine __objectivepgp_X509_REVOKED_delete_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_delete_ext
%xdefine __objectivepgp_X509_REVOKED_get_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext
%xdefine __objectivepgp_X509_REVOKED_get_ext_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_NID
%xdefine __objectivepgp_X509_REVOKED_get_ext_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_OBJ
%xdefine __objectivepgp_X509_REVOKED_get_ext_by_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_critical
%xdefine __objectivepgp_X509_REVOKED_get_ext_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_count
%xdefine __objectivepgp_X509_REVOKED_get_ext_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_d2i
%xdefine __objectivepgp_X509_add1_ext_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_ext_i2d
%xdefine __objectivepgp_X509_add_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_add_ext
%xdefine __objectivepgp_X509_delete_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_delete_ext
%xdefine __objectivepgp_X509_get_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext
%xdefine __objectivepgp_X509_get_ext_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_NID
%xdefine __objectivepgp_X509_get_ext_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_OBJ
%xdefine __objectivepgp_X509_get_ext_by_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_critical
%xdefine __objectivepgp_X509_get_ext_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_count
%xdefine __objectivepgp_X509_get_ext_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_d2i
%xdefine __objectivepgp_X509_LOOKUP_by_alias _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_alias
%xdefine __objectivepgp_X509_LOOKUP_by_fingerprint _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_fingerprint
%xdefine __objectivepgp_X509_LOOKUP_by_issuer_serial _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_issuer_serial
%xdefine __objectivepgp_X509_LOOKUP_by_subject _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_subject
%xdefine __objectivepgp_X509_LOOKUP_ctrl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_ctrl
%xdefine __objectivepgp_X509_LOOKUP_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_free
%xdefine __objectivepgp_X509_LOOKUP_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_init
%xdefine __objectivepgp_X509_LOOKUP_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_new
%xdefine __objectivepgp_X509_LOOKUP_shutdown _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_shutdown
%xdefine __objectivepgp_X509_OBJECT_free_contents _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_free_contents
%xdefine __objectivepgp_X509_OBJECT_get0_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_get0_X509
%xdefine __objectivepgp_X509_OBJECT_get_type _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_get_type
%xdefine __objectivepgp_X509_OBJECT_idx_by_subject _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_idx_by_subject
%xdefine __objectivepgp_X509_OBJECT_retrieve_by_subject _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_retrieve_by_subject
%xdefine __objectivepgp_X509_OBJECT_retrieve_match _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_retrieve_match
%xdefine __objectivepgp_X509_OBJECT_up_ref_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_up_ref_count
%xdefine __objectivepgp_X509_STORE_CTX_get0_store _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_store
%xdefine __objectivepgp_X509_STORE_CTX_get1_issuer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get1_issuer
%xdefine __objectivepgp_X509_STORE_add_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_cert
%xdefine __objectivepgp_X509_STORE_add_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_crl
%xdefine __objectivepgp_X509_STORE_add_lookup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_lookup
%xdefine __objectivepgp_X509_STORE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_free
%xdefine __objectivepgp_X509_STORE_get0_objects _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get0_objects
%xdefine __objectivepgp_X509_STORE_get0_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get0_param
%xdefine __objectivepgp_X509_STORE_get1_certs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get1_certs
%xdefine __objectivepgp_X509_STORE_get1_crls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get1_crls
%xdefine __objectivepgp_X509_STORE_get_by_subject _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_by_subject
%xdefine __objectivepgp_X509_STORE_get_cert_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_cert_crl
%xdefine __objectivepgp_X509_STORE_get_check_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_crl
%xdefine __objectivepgp_X509_STORE_get_check_issued _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_issued
%xdefine __objectivepgp_X509_STORE_get_check_revocation _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_revocation
%xdefine __objectivepgp_X509_STORE_get_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_cleanup
%xdefine __objectivepgp_X509_STORE_get_get_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_get_crl
%xdefine __objectivepgp_X509_STORE_get_get_issuer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_get_issuer
%xdefine __objectivepgp_X509_STORE_get_lookup_certs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_lookup_certs
%xdefine __objectivepgp_X509_STORE_get_lookup_crls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_lookup_crls
%xdefine __objectivepgp_X509_STORE_get_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_verify
%xdefine __objectivepgp_X509_STORE_get_verify_cb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_verify_cb
%xdefine __objectivepgp_X509_STORE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_new
%xdefine __objectivepgp_X509_STORE_set0_additional_untrusted _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set0_additional_untrusted
%xdefine __objectivepgp_X509_STORE_set1_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set1_param
%xdefine __objectivepgp_X509_STORE_set_cert_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_cert_crl
%xdefine __objectivepgp_X509_STORE_set_check_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_crl
%xdefine __objectivepgp_X509_STORE_set_check_issued _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_issued
%xdefine __objectivepgp_X509_STORE_set_check_revocation _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_revocation
%xdefine __objectivepgp_X509_STORE_set_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_cleanup
%xdefine __objectivepgp_X509_STORE_set_depth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_depth
%xdefine __objectivepgp_X509_STORE_set_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_flags
%xdefine __objectivepgp_X509_STORE_set_get_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_get_crl
%xdefine __objectivepgp_X509_STORE_set_get_issuer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_get_issuer
%xdefine __objectivepgp_X509_STORE_set_lookup_certs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_lookup_certs
%xdefine __objectivepgp_X509_STORE_set_lookup_crls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_lookup_crls
%xdefine __objectivepgp_X509_STORE_set_purpose _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_purpose
%xdefine __objectivepgp_X509_STORE_set_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_trust
%xdefine __objectivepgp_X509_STORE_set_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_verify
%xdefine __objectivepgp_X509_STORE_set_verify_cb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_verify_cb
%xdefine __objectivepgp_X509_STORE_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_up_ref
%xdefine __objectivepgp_X509_NAME_oneline _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_oneline
%xdefine __objectivepgp_X509_REQ_to_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_to_X509
%xdefine __objectivepgp_X509_REQ_add1_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr
%xdefine __objectivepgp_X509_REQ_add1_attr_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_NID
%xdefine __objectivepgp_X509_REQ_add1_attr_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_OBJ
%xdefine __objectivepgp_X509_REQ_add1_attr_by_txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_txt
%xdefine __objectivepgp_X509_REQ_add_extensions _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add_extensions
%xdefine __objectivepgp_X509_REQ_add_extensions_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add_extensions_nid
%xdefine __objectivepgp_X509_REQ_check_private_key _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_check_private_key
%xdefine __objectivepgp_X509_REQ_delete_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_delete_attr
%xdefine __objectivepgp_X509_REQ_extension_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_extension_nid
%xdefine __objectivepgp_X509_REQ_get0_signature _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get0_signature
%xdefine __objectivepgp_X509_REQ_get_attr _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr
%xdefine __objectivepgp_X509_REQ_get_attr_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_by_NID
%xdefine __objectivepgp_X509_REQ_get_attr_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_by_OBJ
%xdefine __objectivepgp_X509_REQ_get_attr_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_count
%xdefine __objectivepgp_X509_REQ_get_extension_nids _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_extension_nids
%xdefine __objectivepgp_X509_REQ_get_extensions _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_extensions
%xdefine __objectivepgp_X509_REQ_get_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_pubkey
%xdefine __objectivepgp_X509_REQ_get_signature_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_signature_nid
%xdefine __objectivepgp_X509_REQ_set_extension_nids _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_extension_nids
%xdefine __objectivepgp_X509_to_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_to_X509_REQ
%xdefine __objectivepgp_i2d_re_X509_REQ_tbs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_REQ_tbs
%xdefine __objectivepgp_X509_get0_extensions _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_extensions
%xdefine __objectivepgp_X509_get0_notAfter _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_notAfter
%xdefine __objectivepgp_X509_get0_notBefore _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_notBefore
%xdefine __objectivepgp_X509_get0_tbs_sigalg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_tbs_sigalg
%xdefine __objectivepgp_X509_set_issuer_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_issuer_name
%xdefine __objectivepgp_X509_set_notAfter _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_notAfter
%xdefine __objectivepgp_X509_set_notBefore _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_notBefore
%xdefine __objectivepgp_X509_set_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_pubkey
%xdefine __objectivepgp_X509_set_serialNumber _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_serialNumber
%xdefine __objectivepgp_X509_set_subject_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_subject_name
%xdefine __objectivepgp_X509_set_version _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_version
%xdefine __objectivepgp_X509_TRUST_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_add
%xdefine __objectivepgp_X509_TRUST_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_cleanup
%xdefine __objectivepgp_X509_TRUST_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get0
%xdefine __objectivepgp_X509_TRUST_get0_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get0_name
%xdefine __objectivepgp_X509_TRUST_get_by_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_by_id
%xdefine __objectivepgp_X509_TRUST_get_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_count
%xdefine __objectivepgp_X509_TRUST_get_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_flags
%xdefine __objectivepgp_X509_TRUST_get_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_trust
%xdefine __objectivepgp_X509_TRUST_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_set
%xdefine __objectivepgp_X509_TRUST_set_default _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_set_default
%xdefine __objectivepgp_X509_check_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_trust
%xdefine __objectivepgp_X509_verify_cert_error_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_verify_cert_error_string
%xdefine __objectivepgp_X509_EXTENSION_create_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_create_by_NID
%xdefine __objectivepgp_X509_EXTENSION_create_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_create_by_OBJ
%xdefine __objectivepgp_X509_EXTENSION_get_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_critical
%xdefine __objectivepgp_X509_EXTENSION_get_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_data
%xdefine __objectivepgp_X509_EXTENSION_get_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_object
%xdefine __objectivepgp_X509_EXTENSION_set_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_critical
%xdefine __objectivepgp_X509_EXTENSION_set_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_data
%xdefine __objectivepgp_X509_EXTENSION_set_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_object
%xdefine __objectivepgp_X509v3_add_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_add_ext
%xdefine __objectivepgp_X509v3_delete_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_delete_ext
%xdefine __objectivepgp_X509v3_get_ext _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext
%xdefine __objectivepgp_X509v3_get_ext_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_NID
%xdefine __objectivepgp_X509v3_get_ext_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_OBJ
%xdefine __objectivepgp_X509v3_get_ext_by_critical _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_critical
%xdefine __objectivepgp_X509v3_get_ext_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_count
%xdefine __objectivepgp_X509_CRL_diff _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_diff
%xdefine __objectivepgp_X509_STORE_CTX_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_cleanup
%xdefine __objectivepgp_X509_STORE_CTX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_free
%xdefine __objectivepgp_X509_STORE_CTX_get0_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_cert
%xdefine __objectivepgp_X509_STORE_CTX_get0_current_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_current_crl
%xdefine __objectivepgp_X509_STORE_CTX_get0_current_issuer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_current_issuer
%xdefine __objectivepgp_X509_STORE_CTX_get0_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_param
%xdefine __objectivepgp_X509_STORE_CTX_get0_parent_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_parent_ctx
%xdefine __objectivepgp_X509_STORE_CTX_get0_policy_tree _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_policy_tree
%xdefine __objectivepgp_X509_STORE_CTX_get0_untrusted _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_untrusted
%xdefine __objectivepgp_X509_STORE_CTX_get1_chain _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get1_chain
%xdefine __objectivepgp_X509_STORE_CTX_get_chain _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_chain
%xdefine __objectivepgp_X509_STORE_CTX_get_current_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_current_cert
%xdefine __objectivepgp_X509_STORE_CTX_get_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_error
%xdefine __objectivepgp_X509_STORE_CTX_get_error_depth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_error_depth
%xdefine __objectivepgp_X509_STORE_CTX_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_ex_data
%xdefine __objectivepgp_X509_STORE_CTX_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_ex_new_index
%xdefine __objectivepgp_X509_STORE_CTX_get_explicit_policy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_explicit_policy
%xdefine __objectivepgp_X509_STORE_CTX_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_init
%xdefine __objectivepgp_X509_STORE_CTX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_new
%xdefine __objectivepgp_X509_STORE_CTX_purpose_inherit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_purpose_inherit
%xdefine __objectivepgp_X509_STORE_CTX_set0_crls _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set0_crls
%xdefine __objectivepgp_X509_STORE_CTX_set0_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set0_param
%xdefine __objectivepgp_X509_STORE_CTX_set_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_cert
%xdefine __objectivepgp_X509_STORE_CTX_set_chain _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_chain
%xdefine __objectivepgp_X509_STORE_CTX_set_default _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_default
%xdefine __objectivepgp_X509_STORE_CTX_set_depth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_depth
%xdefine __objectivepgp_X509_STORE_CTX_set_error _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_error
%xdefine __objectivepgp_X509_STORE_CTX_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_ex_data
%xdefine __objectivepgp_X509_STORE_CTX_set_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_flags
%xdefine __objectivepgp_X509_STORE_CTX_set_purpose _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_purpose
%xdefine __objectivepgp_X509_STORE_CTX_set_time _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_time
%xdefine __objectivepgp_X509_STORE_CTX_set_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_trust
%xdefine __objectivepgp_X509_STORE_CTX_set_verify_cb _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_verify_cb
%xdefine __objectivepgp_X509_STORE_CTX_trusted_stack _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_trusted_stack
%xdefine __objectivepgp_X509_STORE_CTX_zero _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_zero
%xdefine __objectivepgp_X509_cmp_current_time _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp_current_time
%xdefine __objectivepgp_X509_cmp_time _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp_time
%xdefine __objectivepgp_X509_gmtime_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_gmtime_adj
%xdefine __objectivepgp_X509_time_adj _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_time_adj
%xdefine __objectivepgp_X509_time_adj_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_time_adj_ex
%xdefine __objectivepgp_X509_verify_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_verify_cert
%xdefine __objectivepgp_X509_VERIFY_PARAM_add0_policy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add0_policy
%xdefine __objectivepgp_X509_VERIFY_PARAM_add0_table _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add0_table
%xdefine __objectivepgp_X509_VERIFY_PARAM_add1_host _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add1_host
%xdefine __objectivepgp_X509_VERIFY_PARAM_clear_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_clear_flags
%xdefine __objectivepgp_X509_VERIFY_PARAM_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_free
%xdefine __objectivepgp_X509_VERIFY_PARAM_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0
%xdefine __objectivepgp_X509_VERIFY_PARAM_get0_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0_name
%xdefine __objectivepgp_X509_VERIFY_PARAM_get0_peername _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0_peername
%xdefine __objectivepgp_X509_VERIFY_PARAM_get_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_count
%xdefine __objectivepgp_X509_VERIFY_PARAM_get_depth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_depth
%xdefine __objectivepgp_X509_VERIFY_PARAM_get_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_flags
%xdefine __objectivepgp_X509_VERIFY_PARAM_inherit _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_inherit
%xdefine __objectivepgp_X509_VERIFY_PARAM_lookup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_lookup
%xdefine __objectivepgp_X509_VERIFY_PARAM_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_new
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_email _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_email
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_host _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_host
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_ip _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_ip
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_ip_asc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_ip_asc
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_name
%xdefine __objectivepgp_X509_VERIFY_PARAM_set1_policies _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_policies
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_depth _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_depth
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_flags
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_hostflags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_hostflags
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_purpose _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_purpose
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_time _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_time
%xdefine __objectivepgp_X509_VERIFY_PARAM_set_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_trust
%xdefine __objectivepgp_X509_VERIFY_PARAM_table_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_table_cleanup
%xdefine __objectivepgp_X509_CRL_get0_lastUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_lastUpdate
%xdefine __objectivepgp_X509_CRL_get0_nextUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_nextUpdate
%xdefine __objectivepgp_X509_CRL_get0_signature _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_signature
%xdefine __objectivepgp_X509_CRL_get_signature_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_signature_nid
%xdefine __objectivepgp_X509_CRL_set_issuer_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_issuer_name
%xdefine __objectivepgp_X509_CRL_set_lastUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_lastUpdate
%xdefine __objectivepgp_X509_CRL_set_nextUpdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_nextUpdate
%xdefine __objectivepgp_X509_CRL_set_version _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_version
%xdefine __objectivepgp_X509_CRL_sort _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sort
%xdefine __objectivepgp_X509_CRL_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_up_ref
%xdefine __objectivepgp_X509_REVOKED_get0_revocationDate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get0_revocationDate
%xdefine __objectivepgp_X509_REVOKED_get0_serialNumber _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get0_serialNumber
%xdefine __objectivepgp_X509_REVOKED_set_revocationDate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_set_revocationDate
%xdefine __objectivepgp_X509_REVOKED_set_serialNumber _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_set_serialNumber
%xdefine __objectivepgp_i2d_re_X509_CRL_tbs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_CRL_tbs
%xdefine __objectivepgp_X509_NAME_ENTRY_create_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_NID
%xdefine __objectivepgp_X509_NAME_ENTRY_create_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_OBJ
%xdefine __objectivepgp_X509_NAME_ENTRY_create_by_txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_txt
%xdefine __objectivepgp_X509_NAME_ENTRY_get_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_get_data
%xdefine __objectivepgp_X509_NAME_ENTRY_get_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_get_object
%xdefine __objectivepgp_X509_NAME_ENTRY_set_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set_data
%xdefine __objectivepgp_X509_NAME_ENTRY_set_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set_object
%xdefine __objectivepgp_X509_NAME_add_entry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry
%xdefine __objectivepgp_X509_NAME_add_entry_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_NID
%xdefine __objectivepgp_X509_NAME_add_entry_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_OBJ
%xdefine __objectivepgp_X509_NAME_add_entry_by_txt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_txt
%xdefine __objectivepgp_X509_NAME_delete_entry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_delete_entry
%xdefine __objectivepgp_X509_NAME_entry_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_entry_count
%xdefine __objectivepgp_X509_NAME_get_entry _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_entry
%xdefine __objectivepgp_X509_NAME_get_index_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_index_by_NID
%xdefine __objectivepgp_X509_NAME_get_index_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_index_by_OBJ
%xdefine __objectivepgp_X509_NAME_get_text_by_NID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_text_by_NID
%xdefine __objectivepgp_X509_NAME_get_text_by_OBJ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_text_by_OBJ
%xdefine __objectivepgp_X509_REQ_set_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_pubkey
%xdefine __objectivepgp_X509_REQ_set_subject_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_subject_name
%xdefine __objectivepgp_X509_REQ_set_version _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_version
%xdefine __objectivepgp_NETSCAPE_SPKI_b64_decode _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_b64_decode
%xdefine __objectivepgp_NETSCAPE_SPKI_b64_encode _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_b64_encode
%xdefine __objectivepgp_NETSCAPE_SPKI_get_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_get_pubkey
%xdefine __objectivepgp_NETSCAPE_SPKI_set_pubkey _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_set_pubkey
%xdefine __objectivepgp_X509_ALGORS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGORS_it
%xdefine __objectivepgp_X509_ALGOR_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_cmp
%xdefine __objectivepgp_X509_ALGOR_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_dup
%xdefine __objectivepgp_X509_ALGOR_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_free
%xdefine __objectivepgp_X509_ALGOR_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_get0
%xdefine __objectivepgp_X509_ALGOR_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_it
%xdefine __objectivepgp_X509_ALGOR_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_new
%xdefine __objectivepgp_X509_ALGOR_set0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_set0
%xdefine __objectivepgp_X509_ALGOR_set_md _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_set_md
%xdefine __objectivepgp_d2i_X509_ALGOR _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ALGOR
%xdefine __objectivepgp_d2i_X509_ALGORS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ALGORS
%xdefine __objectivepgp_i2d_X509_ALGOR _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ALGOR
%xdefine __objectivepgp_i2d_X509_ALGORS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ALGORS
%xdefine __objectivepgp_NETSCAPE_SPKI_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_sign
%xdefine __objectivepgp_NETSCAPE_SPKI_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_verify
%xdefine __objectivepgp_X509_CRL_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_digest
%xdefine __objectivepgp_X509_CRL_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sign
%xdefine __objectivepgp_X509_CRL_sign_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sign_ctx
%xdefine __objectivepgp_X509_NAME_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_digest
%xdefine __objectivepgp_X509_REQ_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_digest
%xdefine __objectivepgp_X509_REQ_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_sign
%xdefine __objectivepgp_X509_REQ_sign_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_sign_ctx
%xdefine __objectivepgp_X509_REQ_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_verify
%xdefine __objectivepgp_X509_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_digest
%xdefine __objectivepgp_X509_pubkey_digest _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_pubkey_digest
%xdefine __objectivepgp_X509_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_sign
%xdefine __objectivepgp_X509_sign_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_sign_ctx
%xdefine __objectivepgp_X509_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_verify
%xdefine __objectivepgp_d2i_DHparams_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DHparams_bio
%xdefine __objectivepgp_d2i_DSAPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey_bio
%xdefine __objectivepgp_d2i_DSAPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey_fp
%xdefine __objectivepgp_d2i_DSA_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY_bio
%xdefine __objectivepgp_d2i_DSA_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY_fp
%xdefine __objectivepgp_d2i_ECPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey_bio
%xdefine __objectivepgp_d2i_ECPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey_fp
%xdefine __objectivepgp_d2i_EC_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY_bio
%xdefine __objectivepgp_d2i_EC_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY_fp
%xdefine __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_bio
%xdefine __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_fp
%xdefine __objectivepgp_d2i_PKCS8_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_bio
%xdefine __objectivepgp_d2i_PKCS8_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_fp
%xdefine __objectivepgp_d2i_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY_bio
%xdefine __objectivepgp_d2i_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY_fp
%xdefine __objectivepgp_d2i_PrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey_bio
%xdefine __objectivepgp_d2i_PrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey_fp
%xdefine __objectivepgp_d2i_RSAPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey_bio
%xdefine __objectivepgp_d2i_RSAPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey_fp
%xdefine __objectivepgp_d2i_RSAPublicKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey_bio
%xdefine __objectivepgp_d2i_RSAPublicKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey_fp
%xdefine __objectivepgp_d2i_RSA_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY_bio
%xdefine __objectivepgp_d2i_RSA_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY_fp
%xdefine __objectivepgp_d2i_X509_CRL_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_bio
%xdefine __objectivepgp_d2i_X509_CRL_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_fp
%xdefine __objectivepgp_d2i_X509_REQ_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_bio
%xdefine __objectivepgp_d2i_X509_REQ_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_fp
%xdefine __objectivepgp_d2i_X509_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_bio
%xdefine __objectivepgp_d2i_X509_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_fp
%xdefine __objectivepgp_i2d_DHparams_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DHparams_bio
%xdefine __objectivepgp_i2d_DSAPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey_bio
%xdefine __objectivepgp_i2d_DSAPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey_fp
%xdefine __objectivepgp_i2d_DSA_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY_bio
%xdefine __objectivepgp_i2d_DSA_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY_fp
%xdefine __objectivepgp_i2d_ECPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey_bio
%xdefine __objectivepgp_i2d_ECPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey_fp
%xdefine __objectivepgp_i2d_EC_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY_bio
%xdefine __objectivepgp_i2d_EC_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY_fp
%xdefine __objectivepgp_i2d_PKCS8PrivateKeyInfo_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKeyInfo_bio
%xdefine __objectivepgp_i2d_PKCS8PrivateKeyInfo_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKeyInfo_fp
%xdefine __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_bio
%xdefine __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_fp
%xdefine __objectivepgp_i2d_PKCS8_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_bio
%xdefine __objectivepgp_i2d_PKCS8_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_fp
%xdefine __objectivepgp_i2d_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY_bio
%xdefine __objectivepgp_i2d_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY_fp
%xdefine __objectivepgp_i2d_PrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey_bio
%xdefine __objectivepgp_i2d_PrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey_fp
%xdefine __objectivepgp_i2d_RSAPrivateKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey_bio
%xdefine __objectivepgp_i2d_RSAPrivateKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey_fp
%xdefine __objectivepgp_i2d_RSAPublicKey_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey_bio
%xdefine __objectivepgp_i2d_RSAPublicKey_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey_fp
%xdefine __objectivepgp_i2d_RSA_PUBKEY_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY_bio
%xdefine __objectivepgp_i2d_RSA_PUBKEY_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY_fp
%xdefine __objectivepgp_i2d_X509_CRL_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_bio
%xdefine __objectivepgp_i2d_X509_CRL_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_fp
%xdefine __objectivepgp_i2d_X509_REQ_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_bio
%xdefine __objectivepgp_i2d_X509_REQ_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_fp
%xdefine __objectivepgp_i2d_X509_bio _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_bio
%xdefine __objectivepgp_i2d_X509_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_fp
%xdefine __objectivepgp_X509_ATTRIBUTE_SET_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_SET_it
%xdefine __objectivepgp_X509_ATTRIBUTE_create _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create
%xdefine __objectivepgp_X509_ATTRIBUTE_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_dup
%xdefine __objectivepgp_X509_ATTRIBUTE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_free
%xdefine __objectivepgp_X509_ATTRIBUTE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_it
%xdefine __objectivepgp_X509_ATTRIBUTE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_new
%xdefine __objectivepgp_d2i_X509_ATTRIBUTE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ATTRIBUTE
%xdefine __objectivepgp_i2d_X509_ATTRIBUTE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ATTRIBUTE
%xdefine __objectivepgp_X509_CRL_INFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_free
%xdefine __objectivepgp_X509_CRL_INFO_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_it
%xdefine __objectivepgp_X509_CRL_INFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_new
%xdefine __objectivepgp_X509_CRL_METHOD_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_METHOD_free
%xdefine __objectivepgp_X509_CRL_METHOD_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_METHOD_new
%xdefine __objectivepgp_X509_CRL_add0_revoked _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add0_revoked
%xdefine __objectivepgp_X509_CRL_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_dup
%xdefine __objectivepgp_X509_CRL_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_free
%xdefine __objectivepgp_X509_CRL_get0_by_cert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_by_cert
%xdefine __objectivepgp_X509_CRL_get0_by_serial _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_by_serial
%xdefine __objectivepgp_X509_CRL_get_meth_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_meth_data
%xdefine __objectivepgp_X509_CRL_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_it
%xdefine __objectivepgp_X509_CRL_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_new
%xdefine __objectivepgp_X509_CRL_set_default_method _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_default_method
%xdefine __objectivepgp_X509_CRL_set_meth_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_meth_data
%xdefine __objectivepgp_X509_CRL_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_verify
%xdefine __objectivepgp_X509_REVOKED_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_dup
%xdefine __objectivepgp_X509_REVOKED_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_free
%xdefine __objectivepgp_X509_REVOKED_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_it
%xdefine __objectivepgp_X509_REVOKED_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_new
%xdefine __objectivepgp_d2i_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL
%xdefine __objectivepgp_d2i_X509_CRL_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_INFO
%xdefine __objectivepgp_d2i_X509_REVOKED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REVOKED
%xdefine __objectivepgp_i2d_X509_CRL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL
%xdefine __objectivepgp_i2d_X509_CRL_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_INFO
%xdefine __objectivepgp_i2d_X509_REVOKED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REVOKED
%xdefine __objectivepgp_X509_EXTENSIONS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSIONS_it
%xdefine __objectivepgp_X509_EXTENSION_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_dup
%xdefine __objectivepgp_X509_EXTENSION_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_free
%xdefine __objectivepgp_X509_EXTENSION_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_it
%xdefine __objectivepgp_X509_EXTENSION_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_new
%xdefine __objectivepgp_d2i_X509_EXTENSION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_EXTENSION
%xdefine __objectivepgp_d2i_X509_EXTENSIONS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_EXTENSIONS
%xdefine __objectivepgp_i2d_X509_EXTENSION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_EXTENSION
%xdefine __objectivepgp_i2d_X509_EXTENSIONS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_EXTENSIONS
%xdefine __objectivepgp_X509_INFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_INFO_free
%xdefine __objectivepgp_X509_INFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_INFO_new
%xdefine __objectivepgp_X509_NAME_ENTRIES_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRIES_it
%xdefine __objectivepgp_X509_NAME_ENTRY_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_dup
%xdefine __objectivepgp_X509_NAME_ENTRY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_free
%xdefine __objectivepgp_X509_NAME_ENTRY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_it
%xdefine __objectivepgp_X509_NAME_ENTRY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_new
%xdefine __objectivepgp_X509_NAME_ENTRY_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set
%xdefine __objectivepgp_X509_NAME_INTERNAL_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_INTERNAL_it
%xdefine __objectivepgp_X509_NAME_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_dup
%xdefine __objectivepgp_X509_NAME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_free
%xdefine __objectivepgp_X509_NAME_get0_der _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get0_der
%xdefine __objectivepgp_X509_NAME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_it
%xdefine __objectivepgp_X509_NAME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_new
%xdefine __objectivepgp_X509_NAME_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_set
%xdefine __objectivepgp_d2i_X509_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_NAME
%xdefine __objectivepgp_d2i_X509_NAME_ENTRY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_NAME_ENTRY
%xdefine __objectivepgp_i2d_X509_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_NAME
%xdefine __objectivepgp_i2d_X509_NAME_ENTRY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_NAME_ENTRY
%xdefine __objectivepgp_X509_PKEY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PKEY_free
%xdefine __objectivepgp_X509_PKEY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PKEY_new
%xdefine __objectivepgp_X509_PUBKEY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_free
%xdefine __objectivepgp_X509_PUBKEY_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_get
%xdefine __objectivepgp_X509_PUBKEY_get0_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_get0_param
%xdefine __objectivepgp_X509_PUBKEY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_it
%xdefine __objectivepgp_X509_PUBKEY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_new
%xdefine __objectivepgp_X509_PUBKEY_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_set
%xdefine __objectivepgp_X509_PUBKEY_set0_param _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_set0_param
%xdefine __objectivepgp_d2i_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY
%xdefine __objectivepgp_d2i_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY
%xdefine __objectivepgp_d2i_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY
%xdefine __objectivepgp_d2i_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY
%xdefine __objectivepgp_d2i_X509_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_PUBKEY
%xdefine __objectivepgp_i2d_DSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY
%xdefine __objectivepgp_i2d_EC_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY
%xdefine __objectivepgp_i2d_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY
%xdefine __objectivepgp_i2d_RSA_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY
%xdefine __objectivepgp_i2d_X509_PUBKEY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_PUBKEY
%xdefine __objectivepgp_X509_REQ_INFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_free
%xdefine __objectivepgp_X509_REQ_INFO_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_it
%xdefine __objectivepgp_X509_REQ_INFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_new
%xdefine __objectivepgp_X509_REQ_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_dup
%xdefine __objectivepgp_X509_REQ_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_free
%xdefine __objectivepgp_X509_REQ_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_it
%xdefine __objectivepgp_X509_REQ_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_new
%xdefine __objectivepgp_d2i_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ
%xdefine __objectivepgp_d2i_X509_REQ_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_INFO
%xdefine __objectivepgp_i2d_X509_REQ _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ
%xdefine __objectivepgp_i2d_X509_REQ_INFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_INFO
%xdefine __objectivepgp_X509_SIG_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_free
%xdefine __objectivepgp_X509_SIG_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_it
%xdefine __objectivepgp_X509_SIG_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_new
%xdefine __objectivepgp_d2i_X509_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_SIG
%xdefine __objectivepgp_i2d_X509_SIG _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_SIG
%xdefine __objectivepgp_NETSCAPE_SPKAC_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_free
%xdefine __objectivepgp_NETSCAPE_SPKAC_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_it
%xdefine __objectivepgp_NETSCAPE_SPKAC_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_new
%xdefine __objectivepgp_NETSCAPE_SPKI_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_free
%xdefine __objectivepgp_NETSCAPE_SPKI_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_it
%xdefine __objectivepgp_NETSCAPE_SPKI_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_new
%xdefine __objectivepgp_d2i_NETSCAPE_SPKAC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_NETSCAPE_SPKAC
%xdefine __objectivepgp_d2i_NETSCAPE_SPKI _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_NETSCAPE_SPKI
%xdefine __objectivepgp_i2d_NETSCAPE_SPKAC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_NETSCAPE_SPKAC
%xdefine __objectivepgp_i2d_NETSCAPE_SPKI _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_NETSCAPE_SPKI
%xdefine __objectivepgp_X509_VAL_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_free
%xdefine __objectivepgp_X509_VAL_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_it
%xdefine __objectivepgp_X509_VAL_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_new
%xdefine __objectivepgp_d2i_X509_VAL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_VAL
%xdefine __objectivepgp_i2d_X509_VAL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_VAL
%xdefine __objectivepgp_X509_CINF_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_free
%xdefine __objectivepgp_X509_CINF_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_it
%xdefine __objectivepgp_X509_CINF_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_new
%xdefine __objectivepgp_X509_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_dup
%xdefine __objectivepgp_X509_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_free
%xdefine __objectivepgp_X509_get0_signature _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_signature
%xdefine __objectivepgp_X509_get_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ex_data
%xdefine __objectivepgp_X509_get_ex_new_index _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ex_new_index
%xdefine __objectivepgp_X509_get_signature_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_signature_nid
%xdefine __objectivepgp_X509_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_it
%xdefine __objectivepgp_X509_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_new
%xdefine __objectivepgp_X509_parse_from_buffer _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_parse_from_buffer
%xdefine __objectivepgp_X509_set_ex_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_set_ex_data
%xdefine __objectivepgp_X509_up_ref _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_up_ref
%xdefine __objectivepgp_d2i_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509
%xdefine __objectivepgp_d2i_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_AUX
%xdefine __objectivepgp_d2i_X509_CINF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CINF
%xdefine __objectivepgp_i2d_X509 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509
%xdefine __objectivepgp_i2d_X509_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_AUX
%xdefine __objectivepgp_i2d_X509_CINF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CINF
%xdefine __objectivepgp_i2d_re_X509_tbs _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_tbs
%xdefine __objectivepgp_X509_CERT_AUX_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_free
%xdefine __objectivepgp_X509_CERT_AUX_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_it
%xdefine __objectivepgp_X509_CERT_AUX_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_new
%xdefine __objectivepgp_X509_add1_reject_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_reject_object
%xdefine __objectivepgp_X509_add1_trust_object _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_trust_object
%xdefine __objectivepgp_X509_alias_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_alias_get0
%xdefine __objectivepgp_X509_alias_set1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_alias_set1
%xdefine __objectivepgp_X509_keyid_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_keyid_get0
%xdefine __objectivepgp_X509_keyid_set1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_keyid_set1
%xdefine __objectivepgp_X509_reject_clear _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_reject_clear
%xdefine __objectivepgp_X509_trust_clear _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_trust_clear
%xdefine __objectivepgp_d2i_X509_CERT_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CERT_AUX
%xdefine __objectivepgp_i2d_X509_CERT_AUX _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CERT_AUX
%xdefine __objectivepgp_policy_cache_find_data _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_find_data
%xdefine __objectivepgp_policy_cache_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_free
%xdefine __objectivepgp_policy_cache_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_set
%xdefine __objectivepgp_policy_data_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_data_free
%xdefine __objectivepgp_policy_data_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_data_new
%xdefine __objectivepgp_X509_policy_level_get0_node _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_level_get0_node
%xdefine __objectivepgp_X509_policy_level_node_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_level_node_count
%xdefine __objectivepgp_X509_policy_node_get0_parent _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_parent
%xdefine __objectivepgp_X509_policy_node_get0_policy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_policy
%xdefine __objectivepgp_X509_policy_node_get0_qualifiers _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_qualifiers
%xdefine __objectivepgp_X509_policy_tree_get0_level _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_level
%xdefine __objectivepgp_X509_policy_tree_get0_policies _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_policies
%xdefine __objectivepgp_X509_policy_tree_get0_user_policies _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_user_policies
%xdefine __objectivepgp_X509_policy_tree_level_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_level_count
%xdefine __objectivepgp_policy_cache_set_mapping _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_set_mapping
%xdefine __objectivepgp_level_add_node _ %+ BORINGSSL_PREFIX %+ __objectivepgp_level_add_node
%xdefine __objectivepgp_level_find_node _ %+ BORINGSSL_PREFIX %+ __objectivepgp_level_find_node
%xdefine __objectivepgp_policy_node_cmp_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_node_cmp_new
%xdefine __objectivepgp_policy_node_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_node_free
%xdefine __objectivepgp_policy_node_match _ %+ BORINGSSL_PREFIX %+ __objectivepgp_policy_node_match
%xdefine __objectivepgp_tree_find_sk _ %+ BORINGSSL_PREFIX %+ __objectivepgp_tree_find_sk
%xdefine __objectivepgp_X509_policy_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_check
%xdefine __objectivepgp_X509_policy_tree_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_free
%xdefine __objectivepgp_v3_akey_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_akey_id
%xdefine __objectivepgp_AUTHORITY_KEYID_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_free
%xdefine __objectivepgp_AUTHORITY_KEYID_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_it
%xdefine __objectivepgp_AUTHORITY_KEYID_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_new
%xdefine __objectivepgp_d2i_AUTHORITY_KEYID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_AUTHORITY_KEYID
%xdefine __objectivepgp_i2d_AUTHORITY_KEYID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_AUTHORITY_KEYID
%xdefine __objectivepgp_GENERAL_NAME_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_print
%xdefine __objectivepgp_a2i_GENERAL_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_a2i_GENERAL_NAME
%xdefine __objectivepgp_i2v_GENERAL_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2v_GENERAL_NAME
%xdefine __objectivepgp_i2v_GENERAL_NAMES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2v_GENERAL_NAMES
%xdefine __objectivepgp_v2i_GENERAL_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAME
%xdefine __objectivepgp_v2i_GENERAL_NAMES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAMES
%xdefine __objectivepgp_v2i_GENERAL_NAME_ex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAME_ex
%xdefine __objectivepgp_v3_alt _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_alt
%xdefine __objectivepgp_BASIC_CONSTRAINTS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_free
%xdefine __objectivepgp_BASIC_CONSTRAINTS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_it
%xdefine __objectivepgp_BASIC_CONSTRAINTS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_new
%xdefine __objectivepgp_d2i_BASIC_CONSTRAINTS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_BASIC_CONSTRAINTS
%xdefine __objectivepgp_i2d_BASIC_CONSTRAINTS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_BASIC_CONSTRAINTS
%xdefine __objectivepgp_v3_bcons _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_bcons
%xdefine __objectivepgp_i2v_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2v_ASN1_BIT_STRING
%xdefine __objectivepgp_v2i_ASN1_BIT_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v2i_ASN1_BIT_STRING
%xdefine __objectivepgp_v3_key_usage _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_key_usage
%xdefine __objectivepgp_v3_nscert _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_nscert
%xdefine __objectivepgp_X509V3_EXT_CRL_add_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_CRL_add_nconf
%xdefine __objectivepgp_X509V3_EXT_REQ_add_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_REQ_add_nconf
%xdefine __objectivepgp_X509V3_EXT_add_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_nconf
%xdefine __objectivepgp_X509V3_EXT_add_nconf_sk _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_nconf_sk
%xdefine __objectivepgp_X509V3_EXT_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_i2d
%xdefine __objectivepgp_X509V3_EXT_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_nconf
%xdefine __objectivepgp_X509V3_EXT_nconf_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_nconf_nid
%xdefine __objectivepgp_X509V3_get_section _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_section
%xdefine __objectivepgp_X509V3_get_string _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_string
%xdefine __objectivepgp_X509V3_section_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_section_free
%xdefine __objectivepgp_X509V3_set_ctx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_set_ctx
%xdefine __objectivepgp_X509V3_set_nconf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_set_nconf
%xdefine __objectivepgp_X509V3_string_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_string_free
%xdefine __objectivepgp_CERTIFICATEPOLICIES_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_free
%xdefine __objectivepgp_CERTIFICATEPOLICIES_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_it
%xdefine __objectivepgp_CERTIFICATEPOLICIES_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_new
%xdefine __objectivepgp_NOTICEREF_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_free
%xdefine __objectivepgp_NOTICEREF_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_it
%xdefine __objectivepgp_NOTICEREF_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_new
%xdefine __objectivepgp_POLICYINFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_free
%xdefine __objectivepgp_POLICYINFO_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_it
%xdefine __objectivepgp_POLICYINFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_new
%xdefine __objectivepgp_POLICYQUALINFO_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_free
%xdefine __objectivepgp_POLICYQUALINFO_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_it
%xdefine __objectivepgp_POLICYQUALINFO_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_new
%xdefine __objectivepgp_USERNOTICE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_free
%xdefine __objectivepgp_USERNOTICE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_it
%xdefine __objectivepgp_USERNOTICE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_new
%xdefine __objectivepgp_X509_POLICY_NODE_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_POLICY_NODE_print
%xdefine __objectivepgp_d2i_CERTIFICATEPOLICIES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_CERTIFICATEPOLICIES
%xdefine __objectivepgp_d2i_NOTICEREF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_NOTICEREF
%xdefine __objectivepgp_d2i_POLICYINFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_POLICYINFO
%xdefine __objectivepgp_d2i_POLICYQUALINFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_POLICYQUALINFO
%xdefine __objectivepgp_d2i_USERNOTICE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_USERNOTICE
%xdefine __objectivepgp_i2d_CERTIFICATEPOLICIES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_CERTIFICATEPOLICIES
%xdefine __objectivepgp_i2d_NOTICEREF _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_NOTICEREF
%xdefine __objectivepgp_i2d_POLICYINFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_POLICYINFO
%xdefine __objectivepgp_i2d_POLICYQUALINFO _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_POLICYQUALINFO
%xdefine __objectivepgp_i2d_USERNOTICE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_USERNOTICE
%xdefine __objectivepgp_v3_cpols _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_cpols
%xdefine __objectivepgp_CRL_DIST_POINTS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_free
%xdefine __objectivepgp_CRL_DIST_POINTS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_it
%xdefine __objectivepgp_CRL_DIST_POINTS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_new
%xdefine __objectivepgp_DIST_POINT_NAME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_free
%xdefine __objectivepgp_DIST_POINT_NAME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_it
%xdefine __objectivepgp_DIST_POINT_NAME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_new
%xdefine __objectivepgp_DIST_POINT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_free
%xdefine __objectivepgp_DIST_POINT_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_it
%xdefine __objectivepgp_DIST_POINT_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_new
%xdefine __objectivepgp_DIST_POINT_set_dpname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_set_dpname
%xdefine __objectivepgp_ISSUING_DIST_POINT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_free
%xdefine __objectivepgp_ISSUING_DIST_POINT_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_it
%xdefine __objectivepgp_ISSUING_DIST_POINT_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_new
%xdefine __objectivepgp_d2i_CRL_DIST_POINTS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_CRL_DIST_POINTS
%xdefine __objectivepgp_d2i_DIST_POINT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIST_POINT
%xdefine __objectivepgp_d2i_DIST_POINT_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIST_POINT_NAME
%xdefine __objectivepgp_d2i_ISSUING_DIST_POINT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ISSUING_DIST_POINT
%xdefine __objectivepgp_i2d_CRL_DIST_POINTS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_CRL_DIST_POINTS
%xdefine __objectivepgp_i2d_DIST_POINT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIST_POINT
%xdefine __objectivepgp_i2d_DIST_POINT_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIST_POINT_NAME
%xdefine __objectivepgp_i2d_ISSUING_DIST_POINT _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ISSUING_DIST_POINT
%xdefine __objectivepgp_v3_crld _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_crld
%xdefine __objectivepgp_v3_freshest_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_freshest_crl
%xdefine __objectivepgp_v3_idp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_idp
%xdefine __objectivepgp_i2s_ASN1_ENUMERATED_TABLE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_ENUMERATED_TABLE
%xdefine __objectivepgp_v3_crl_reason _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_reason
%xdefine __objectivepgp_EXTENDED_KEY_USAGE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_free
%xdefine __objectivepgp_EXTENDED_KEY_USAGE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_it
%xdefine __objectivepgp_EXTENDED_KEY_USAGE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_new
%xdefine __objectivepgp_d2i_EXTENDED_KEY_USAGE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_EXTENDED_KEY_USAGE
%xdefine __objectivepgp_i2d_EXTENDED_KEY_USAGE _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_EXTENDED_KEY_USAGE
%xdefine __objectivepgp_v3_ext_ku _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_ext_ku
%xdefine __objectivepgp_v3_ocsp_accresp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_ocsp_accresp
%xdefine __objectivepgp_EDIPARTYNAME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_free
%xdefine __objectivepgp_EDIPARTYNAME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_it
%xdefine __objectivepgp_EDIPARTYNAME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_new
%xdefine __objectivepgp_GENERAL_NAMES_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_free
%xdefine __objectivepgp_GENERAL_NAMES_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_it
%xdefine __objectivepgp_GENERAL_NAMES_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_new
%xdefine __objectivepgp_GENERAL_NAME_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_cmp
%xdefine __objectivepgp_GENERAL_NAME_dup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_dup
%xdefine __objectivepgp_GENERAL_NAME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_free
%xdefine __objectivepgp_GENERAL_NAME_get0_otherName _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_get0_otherName
%xdefine __objectivepgp_GENERAL_NAME_get0_value _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_get0_value
%xdefine __objectivepgp_GENERAL_NAME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_it
%xdefine __objectivepgp_GENERAL_NAME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_new
%xdefine __objectivepgp_GENERAL_NAME_set0_othername _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_set0_othername
%xdefine __objectivepgp_GENERAL_NAME_set0_value _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_set0_value
%xdefine __objectivepgp_OTHERNAME_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_cmp
%xdefine __objectivepgp_OTHERNAME_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_free
%xdefine __objectivepgp_OTHERNAME_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_it
%xdefine __objectivepgp_OTHERNAME_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_new
%xdefine __objectivepgp_d2i_EDIPARTYNAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_EDIPARTYNAME
%xdefine __objectivepgp_d2i_GENERAL_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_GENERAL_NAME
%xdefine __objectivepgp_d2i_GENERAL_NAMES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_GENERAL_NAMES
%xdefine __objectivepgp_d2i_OTHERNAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_OTHERNAME
%xdefine __objectivepgp_i2d_EDIPARTYNAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_EDIPARTYNAME
%xdefine __objectivepgp_i2d_GENERAL_NAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_GENERAL_NAME
%xdefine __objectivepgp_i2d_GENERAL_NAMES _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_GENERAL_NAMES
%xdefine __objectivepgp_i2d_OTHERNAME _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_OTHERNAME
%xdefine __objectivepgp_v3_ns_ia5_list _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_ns_ia5_list
%xdefine __objectivepgp_ACCESS_DESCRIPTION_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_free
%xdefine __objectivepgp_ACCESS_DESCRIPTION_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_it
%xdefine __objectivepgp_ACCESS_DESCRIPTION_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_new
%xdefine __objectivepgp_AUTHORITY_INFO_ACCESS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_free
%xdefine __objectivepgp_AUTHORITY_INFO_ACCESS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_it
%xdefine __objectivepgp_AUTHORITY_INFO_ACCESS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_new
%xdefine __objectivepgp_d2i_ACCESS_DESCRIPTION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_ACCESS_DESCRIPTION
%xdefine __objectivepgp_d2i_AUTHORITY_INFO_ACCESS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_AUTHORITY_INFO_ACCESS
%xdefine __objectivepgp_i2a_ACCESS_DESCRIPTION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2a_ACCESS_DESCRIPTION
%xdefine __objectivepgp_i2d_ACCESS_DESCRIPTION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_ACCESS_DESCRIPTION
%xdefine __objectivepgp_i2d_AUTHORITY_INFO_ACCESS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_AUTHORITY_INFO_ACCESS
%xdefine __objectivepgp_v3_info _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_info
%xdefine __objectivepgp_v3_sinfo _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_sinfo
%xdefine __objectivepgp_v3_crl_num _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_num
%xdefine __objectivepgp_v3_delta_crl _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_delta_crl
%xdefine __objectivepgp_v3_inhibit_anyp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_inhibit_anyp
%xdefine __objectivepgp_X509V3_EXT_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add
%xdefine __objectivepgp_X509V3_EXT_add_alias _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_alias
%xdefine __objectivepgp_X509V3_EXT_add_list _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_list
%xdefine __objectivepgp_X509V3_EXT_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_cleanup
%xdefine __objectivepgp_X509V3_EXT_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_d2i
%xdefine __objectivepgp_X509V3_EXT_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_free
%xdefine __objectivepgp_X509V3_EXT_get _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_get
%xdefine __objectivepgp_X509V3_EXT_get_nid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_get_nid
%xdefine __objectivepgp_X509V3_add1_i2d _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add1_i2d
%xdefine __objectivepgp_X509V3_add_standard_extensions _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_standard_extensions
%xdefine __objectivepgp_X509V3_get_d2i _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_d2i
%xdefine __objectivepgp_GENERAL_SUBTREE_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_free
%xdefine __objectivepgp_GENERAL_SUBTREE_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_it
%xdefine __objectivepgp_GENERAL_SUBTREE_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_new
%xdefine __objectivepgp_NAME_CONSTRAINTS_check _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_check
%xdefine __objectivepgp_NAME_CONSTRAINTS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_free
%xdefine __objectivepgp_NAME_CONSTRAINTS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_it
%xdefine __objectivepgp_NAME_CONSTRAINTS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_new
%xdefine __objectivepgp_v3_name_constraints _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_name_constraints
%xdefine __objectivepgp_v3_crl_invdate _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_invdate
%xdefine __objectivepgp_v3_ocsp_nocheck _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_ocsp_nocheck
%xdefine __objectivepgp_v3_pci _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_pci
%xdefine __objectivepgp_PROXY_CERT_INFO_EXTENSION_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_free
%xdefine __objectivepgp_PROXY_CERT_INFO_EXTENSION_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_it
%xdefine __objectivepgp_PROXY_CERT_INFO_EXTENSION_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_new
%xdefine __objectivepgp_PROXY_POLICY_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_free
%xdefine __objectivepgp_PROXY_POLICY_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_it
%xdefine __objectivepgp_PROXY_POLICY_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_new
%xdefine __objectivepgp_d2i_PROXY_CERT_INFO_EXTENSION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PROXY_CERT_INFO_EXTENSION
%xdefine __objectivepgp_d2i_PROXY_POLICY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PROXY_POLICY
%xdefine __objectivepgp_i2d_PROXY_CERT_INFO_EXTENSION _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PROXY_CERT_INFO_EXTENSION
%xdefine __objectivepgp_i2d_PROXY_POLICY _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PROXY_POLICY
%xdefine __objectivepgp_POLICY_CONSTRAINTS_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_free
%xdefine __objectivepgp_POLICY_CONSTRAINTS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_it
%xdefine __objectivepgp_POLICY_CONSTRAINTS_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_new
%xdefine __objectivepgp_v3_policy_constraints _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_policy_constraints
%xdefine __objectivepgp_PKEY_USAGE_PERIOD_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_free
%xdefine __objectivepgp_PKEY_USAGE_PERIOD_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_it
%xdefine __objectivepgp_PKEY_USAGE_PERIOD_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_new
%xdefine __objectivepgp_d2i_PKEY_USAGE_PERIOD _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKEY_USAGE_PERIOD
%xdefine __objectivepgp_i2d_PKEY_USAGE_PERIOD _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKEY_USAGE_PERIOD
%xdefine __objectivepgp_v3_pkey_usage_period _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_pkey_usage_period
%xdefine __objectivepgp_POLICY_MAPPINGS_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPINGS_it
%xdefine __objectivepgp_POLICY_MAPPING_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_free
%xdefine __objectivepgp_POLICY_MAPPING_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_it
%xdefine __objectivepgp_POLICY_MAPPING_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_new
%xdefine __objectivepgp_v3_policy_mappings _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_policy_mappings
%xdefine __objectivepgp_X509V3_EXT_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_print
%xdefine __objectivepgp_X509V3_EXT_print_fp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_print_fp
%xdefine __objectivepgp_X509V3_EXT_val_prn _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_val_prn
%xdefine __objectivepgp_X509V3_extensions_print _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_extensions_print
%xdefine __objectivepgp_X509_PURPOSE_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_add
%xdefine __objectivepgp_X509_PURPOSE_cleanup _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_cleanup
%xdefine __objectivepgp_X509_PURPOSE_get0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0
%xdefine __objectivepgp_X509_PURPOSE_get0_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0_name
%xdefine __objectivepgp_X509_PURPOSE_get0_sname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0_sname
%xdefine __objectivepgp_X509_PURPOSE_get_by_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_by_id
%xdefine __objectivepgp_X509_PURPOSE_get_by_sname _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_by_sname
%xdefine __objectivepgp_X509_PURPOSE_get_count _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_count
%xdefine __objectivepgp_X509_PURPOSE_get_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_id
%xdefine __objectivepgp_X509_PURPOSE_get_trust _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_trust
%xdefine __objectivepgp_X509_PURPOSE_set _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_set
%xdefine __objectivepgp_X509_check_akid _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_akid
%xdefine __objectivepgp_X509_check_ca _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ca
%xdefine __objectivepgp_X509_check_issued _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_issued
%xdefine __objectivepgp_X509_check_purpose _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_purpose
%xdefine __objectivepgp_X509_get_extended_key_usage _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_extended_key_usage
%xdefine __objectivepgp_X509_get_extension_flags _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_extension_flags
%xdefine __objectivepgp_X509_get_key_usage _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_key_usage
%xdefine __objectivepgp_X509_supported_extension _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_supported_extension
%xdefine __objectivepgp_i2s_ASN1_OCTET_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_OCTET_STRING
%xdefine __objectivepgp_s2i_ASN1_OCTET_STRING _ %+ BORINGSSL_PREFIX %+ __objectivepgp_s2i_ASN1_OCTET_STRING
%xdefine __objectivepgp_v3_skey_id _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_skey_id
%xdefine __objectivepgp_SXNETID_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_free
%xdefine __objectivepgp_SXNETID_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_it
%xdefine __objectivepgp_SXNETID_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_new
%xdefine __objectivepgp_SXNET_add_id_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_INTEGER
%xdefine __objectivepgp_SXNET_add_id_asc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_asc
%xdefine __objectivepgp_SXNET_add_id_ulong _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_ulong
%xdefine __objectivepgp_SXNET_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_free
%xdefine __objectivepgp_SXNET_get_id_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_INTEGER
%xdefine __objectivepgp_SXNET_get_id_asc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_asc
%xdefine __objectivepgp_SXNET_get_id_ulong _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_ulong
%xdefine __objectivepgp_SXNET_it _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_it
%xdefine __objectivepgp_SXNET_new _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SXNET_new
%xdefine __objectivepgp_d2i_SXNET _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_SXNET
%xdefine __objectivepgp_d2i_SXNETID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_d2i_SXNETID
%xdefine __objectivepgp_i2d_SXNET _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_SXNET
%xdefine __objectivepgp_i2d_SXNETID _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2d_SXNETID
%xdefine __objectivepgp_v3_sxnet _ %+ BORINGSSL_PREFIX %+ __objectivepgp_v3_sxnet
%xdefine __objectivepgp_X509V3_NAME_from_section _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_NAME_from_section
%xdefine __objectivepgp_X509V3_add_value _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value
%xdefine __objectivepgp_X509V3_add_value_bool _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_bool
%xdefine __objectivepgp_X509V3_add_value_bool_nf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_bool_nf
%xdefine __objectivepgp_X509V3_add_value_int _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_int
%xdefine __objectivepgp_X509V3_add_value_uchar _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_uchar
%xdefine __objectivepgp_X509V3_conf_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_conf_free
%xdefine __objectivepgp_X509V3_get_value_bool _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_value_bool
%xdefine __objectivepgp_X509V3_get_value_int _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_value_int
%xdefine __objectivepgp_X509V3_parse_list _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509V3_parse_list
%xdefine __objectivepgp_X509_REQ_get1_email _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get1_email
%xdefine __objectivepgp_X509_check_email _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_email
%xdefine __objectivepgp_X509_check_host _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_host
%xdefine __objectivepgp_X509_check_ip _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ip
%xdefine __objectivepgp_X509_check_ip_asc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ip_asc
%xdefine __objectivepgp_X509_email_free _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_email_free
%xdefine __objectivepgp_X509_get1_email _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get1_email
%xdefine __objectivepgp_X509_get1_ocsp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X509_get1_ocsp
%xdefine __objectivepgp_a2i_IPADDRESS _ %+ BORINGSSL_PREFIX %+ __objectivepgp_a2i_IPADDRESS
%xdefine __objectivepgp_a2i_IPADDRESS_NC _ %+ BORINGSSL_PREFIX %+ __objectivepgp_a2i_IPADDRESS_NC
%xdefine __objectivepgp_a2i_ipadd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_a2i_ipadd
%xdefine __objectivepgp_i2s_ASN1_ENUMERATED _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_ENUMERATED
%xdefine __objectivepgp_i2s_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_INTEGER
%xdefine __objectivepgp_s2i_ASN1_INTEGER _ %+ BORINGSSL_PREFIX %+ __objectivepgp_s2i_ASN1_INTEGER
%xdefine __objectivepgp_x509v3_bytes_to_hex _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509v3_bytes_to_hex
%xdefine __objectivepgp_x509v3_hex_to_bytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509v3_hex_to_bytes
%xdefine __objectivepgp_x509v3_looks_like_dns_name _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509v3_looks_like_dns_name
%xdefine __objectivepgp_x509v3_name_cmp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x509v3_name_cmp
%xdefine __objectivepgp_ED25519_keypair _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ED25519_keypair
%xdefine __objectivepgp_ED25519_keypair_from_seed _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ED25519_keypair_from_seed
%xdefine __objectivepgp_ED25519_sign _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ED25519_sign
%xdefine __objectivepgp_ED25519_verify _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ED25519_verify
%xdefine __objectivepgp_X25519 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X25519
%xdefine __objectivepgp_X25519_keypair _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X25519_keypair
%xdefine __objectivepgp_X25519_public_from_private _ %+ BORINGSSL_PREFIX %+ __objectivepgp_X25519_public_from_private
%xdefine __objectivepgp_x25519_ge_add _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_add
%xdefine __objectivepgp_x25519_ge_frombytes_vartime _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_frombytes_vartime
%xdefine __objectivepgp_x25519_ge_p1p1_to_p2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p1p1_to_p2
%xdefine __objectivepgp_x25519_ge_p1p1_to_p3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p1p1_to_p3
%xdefine __objectivepgp_x25519_ge_p3_to_cached _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p3_to_cached
%xdefine __objectivepgp_x25519_ge_scalarmult _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult
%xdefine __objectivepgp_x25519_ge_scalarmult_base _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult_base
%xdefine __objectivepgp_x25519_ge_scalarmult_small_precomp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult_small_precomp
%xdefine __objectivepgp_x25519_ge_sub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_sub
%xdefine __objectivepgp_x25519_ge_tobytes _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_tobytes
%xdefine __objectivepgp_x25519_sc_reduce _ %+ BORINGSSL_PREFIX %+ __objectivepgp_x25519_sc_reduce
%xdefine __objectivepgp_sike_fp2inv_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2inv_mont
%xdefine __objectivepgp_sike_fp2mul_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2mul_mont
%xdefine __objectivepgp_sike_fp2sqr_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2sqr_mont
%xdefine __objectivepgp_sike_fpcopy _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpcopy
%xdefine __objectivepgp_sike_fpcorrection _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpcorrection
%xdefine __objectivepgp_sike_fpdiv2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpdiv2
%xdefine __objectivepgp_sike_fpmul_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpmul_mont
%xdefine __objectivepgp_sike_fpneg _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpneg
%xdefine __objectivepgp_sike_from_mont _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_from_mont
%xdefine __objectivepgp_sike_eval_3_isog _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_eval_3_isog
%xdefine __objectivepgp_sike_eval_4_isog _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_eval_4_isog
%xdefine __objectivepgp_sike_get_3_isog _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_get_3_isog
%xdefine __objectivepgp_sike_get_4_isog _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_get_4_isog
%xdefine __objectivepgp_sike_get_A _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_get_A
%xdefine __objectivepgp_sike_inv_3_way _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_inv_3_way
%xdefine __objectivepgp_sike_j_inv _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_j_inv
%xdefine __objectivepgp_sike_xDBLADD _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_xDBLADD
%xdefine __objectivepgp_sike_xDBLe _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_xDBLe
%xdefine __objectivepgp_sike_xTPL _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_xTPL
%xdefine __objectivepgp_sike_xTPLe _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_xTPLe
%xdefine __objectivepgp_sike_params _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_params
%xdefine __objectivepgp_SIKE_decaps _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SIKE_decaps
%xdefine __objectivepgp_SIKE_encaps _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SIKE_encaps
%xdefine __objectivepgp_SIKE_keypair _ %+ BORINGSSL_PREFIX %+ __objectivepgp_SIKE_keypair
%xdefine __objectivepgp_ChaCha20_ctr32 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_ChaCha20_ctr32
%xdefine __objectivepgp_aes128gcmsiv_aes_ks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_aes_ks
%xdefine __objectivepgp_aes128gcmsiv_aes_ks_enc_x1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_aes_ks_enc_x1
%xdefine __objectivepgp_aes128gcmsiv_dec _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_dec
%xdefine __objectivepgp_aes128gcmsiv_ecb_enc_block _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_ecb_enc_block
%xdefine __objectivepgp_aes128gcmsiv_enc_msg_x4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_enc_msg_x4
%xdefine __objectivepgp_aes128gcmsiv_enc_msg_x8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_enc_msg_x8
%xdefine __objectivepgp_aes128gcmsiv_kdf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_kdf
%xdefine __objectivepgp_aes256gcmsiv_aes_ks _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_aes_ks
%xdefine __objectivepgp_aes256gcmsiv_aes_ks_enc_x1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_aes_ks_enc_x1
%xdefine __objectivepgp_aes256gcmsiv_dec _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_dec
%xdefine __objectivepgp_aes256gcmsiv_ecb_enc_block _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_ecb_enc_block
%xdefine __objectivepgp_aes256gcmsiv_enc_msg_x4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_enc_msg_x4
%xdefine __objectivepgp_aes256gcmsiv_enc_msg_x8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_enc_msg_x8
%xdefine __objectivepgp_aes256gcmsiv_kdf _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_kdf
%xdefine __objectivepgp_aesgcmsiv_htable6_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable6_init
%xdefine __objectivepgp_aesgcmsiv_htable_init _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable_init
%xdefine __objectivepgp_aesgcmsiv_htable_polyval _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable_polyval
%xdefine __objectivepgp_aesgcmsiv_polyval_horner _ %+ BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_polyval_horner
%xdefine __objectivepgp_chacha20_poly1305_open _ %+ BORINGSSL_PREFIX %+ __objectivepgp_chacha20_poly1305_open
%xdefine __objectivepgp_chacha20_poly1305_seal _ %+ BORINGSSL_PREFIX %+ __objectivepgp_chacha20_poly1305_seal
%xdefine __objectivepgp_abi_test_bad_unwind_temporary _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_bad_unwind_temporary
%xdefine __objectivepgp_abi_test_bad_unwind_wrong_register _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_bad_unwind_wrong_register
%xdefine __objectivepgp_abi_test_clobber_r10 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r10
%xdefine __objectivepgp_abi_test_clobber_r11 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r11
%xdefine __objectivepgp_abi_test_clobber_r12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r12
%xdefine __objectivepgp_abi_test_clobber_r13 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r13
%xdefine __objectivepgp_abi_test_clobber_r14 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r14
%xdefine __objectivepgp_abi_test_clobber_r15 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r15
%xdefine __objectivepgp_abi_test_clobber_r8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r8
%xdefine __objectivepgp_abi_test_clobber_r9 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r9
%xdefine __objectivepgp_abi_test_clobber_rax _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rax
%xdefine __objectivepgp_abi_test_clobber_rbp _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rbp
%xdefine __objectivepgp_abi_test_clobber_rbx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rbx
%xdefine __objectivepgp_abi_test_clobber_rcx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rcx
%xdefine __objectivepgp_abi_test_clobber_rdi _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rdi
%xdefine __objectivepgp_abi_test_clobber_rdx _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rdx
%xdefine __objectivepgp_abi_test_clobber_rsi _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rsi
%xdefine __objectivepgp_abi_test_clobber_xmm0 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm0
%xdefine __objectivepgp_abi_test_clobber_xmm1 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm1
%xdefine __objectivepgp_abi_test_clobber_xmm10 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm10
%xdefine __objectivepgp_abi_test_clobber_xmm11 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm11
%xdefine __objectivepgp_abi_test_clobber_xmm12 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm12
%xdefine __objectivepgp_abi_test_clobber_xmm13 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm13
%xdefine __objectivepgp_abi_test_clobber_xmm14 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm14
%xdefine __objectivepgp_abi_test_clobber_xmm15 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm15
%xdefine __objectivepgp_abi_test_clobber_xmm2 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm2
%xdefine __objectivepgp_abi_test_clobber_xmm3 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm3
%xdefine __objectivepgp_abi_test_clobber_xmm4 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm4
%xdefine __objectivepgp_abi_test_clobber_xmm5 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm5
%xdefine __objectivepgp_abi_test_clobber_xmm6 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm6
%xdefine __objectivepgp_abi_test_clobber_xmm7 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm7
%xdefine __objectivepgp_abi_test_clobber_xmm8 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm8
%xdefine __objectivepgp_abi_test_clobber_xmm9 _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm9
%xdefine __objectivepgp_abi_test_get_and_clear_direction_flag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_get_and_clear_direction_flag
%xdefine __objectivepgp_abi_test_set_direction_flag _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_set_direction_flag
%xdefine __objectivepgp_abi_test_trampoline _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_trampoline
%xdefine __objectivepgp_abi_test_unwind_return _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_return
%xdefine __objectivepgp_abi_test_unwind_start _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_start
%xdefine __objectivepgp_abi_test_unwind_stop _ %+ BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_stop
%xdefine __objectivepgp_sike_cswap_asm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_cswap_asm
%xdefine __objectivepgp_sike_fpadd _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpadd
%xdefine __objectivepgp_sike_fprdc _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fprdc
%xdefine __objectivepgp_sike_fpsub _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_fpsub
%xdefine __objectivepgp_sike_mpadd_asm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_mpadd_asm
%xdefine __objectivepgp_sike_mpdblsubx2_asm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_mpdblsubx2_asm
%xdefine __objectivepgp_sike_mpmul _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_mpmul
%xdefine __objectivepgp_sike_mpsubx2_asm _ %+ BORINGSSL_PREFIX %+ __objectivepgp_sike_mpsubx2_asm
%else
%xdefine _objectivepgp_AES_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_cbc_encrypt
%xdefine _objectivepgp_AES_cfb128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_cfb128_encrypt
%xdefine _objectivepgp_AES_ctr128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_ctr128_encrypt
%xdefine _objectivepgp_AES_decrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_decrypt
%xdefine _objectivepgp_AES_ecb_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_ecb_encrypt
%xdefine _objectivepgp_AES_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_encrypt
%xdefine _objectivepgp_AES_ofb128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_AES_ofb128_encrypt
%xdefine _objectivepgp_AES_set_decrypt_key BORINGSSL_PREFIX %+ __objectivepgp_AES_set_decrypt_key
%xdefine _objectivepgp_AES_set_encrypt_key BORINGSSL_PREFIX %+ __objectivepgp_AES_set_encrypt_key
%xdefine _objectivepgp_AES_unwrap_key BORINGSSL_PREFIX %+ __objectivepgp_AES_unwrap_key
%xdefine _objectivepgp_AES_unwrap_key_padded BORINGSSL_PREFIX %+ __objectivepgp_AES_unwrap_key_padded
%xdefine _objectivepgp_AES_wrap_key BORINGSSL_PREFIX %+ __objectivepgp_AES_wrap_key
%xdefine _objectivepgp_AES_wrap_key_padded BORINGSSL_PREFIX %+ __objectivepgp_AES_wrap_key_padded
%xdefine _objectivepgp_BN_BLINDING_convert BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_convert
%xdefine _objectivepgp_BN_BLINDING_free BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_free
%xdefine _objectivepgp_BN_BLINDING_invert BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_invert
%xdefine _objectivepgp_BN_BLINDING_new BORINGSSL_PREFIX %+ __objectivepgp_BN_BLINDING_new
%xdefine _objectivepgp_BN_CTX_end BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_end
%xdefine _objectivepgp_BN_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_free
%xdefine _objectivepgp_BN_CTX_get BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_get
%xdefine _objectivepgp_BN_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_new
%xdefine _objectivepgp_BN_CTX_start BORINGSSL_PREFIX %+ __objectivepgp_BN_CTX_start
%xdefine _objectivepgp_BN_GENCB_call BORINGSSL_PREFIX %+ __objectivepgp_BN_GENCB_call
%xdefine _objectivepgp_BN_GENCB_set BORINGSSL_PREFIX %+ __objectivepgp_BN_GENCB_set
%xdefine _objectivepgp_BN_MONT_CTX_copy BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_copy
%xdefine _objectivepgp_BN_MONT_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_free
%xdefine _objectivepgp_BN_MONT_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new
%xdefine _objectivepgp_BN_MONT_CTX_new_consttime BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new_consttime
%xdefine _objectivepgp_BN_MONT_CTX_new_for_modulus BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_new_for_modulus
%xdefine _objectivepgp_BN_MONT_CTX_set BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_set
%xdefine _objectivepgp_BN_MONT_CTX_set_locked BORINGSSL_PREFIX %+ __objectivepgp_BN_MONT_CTX_set_locked
%xdefine _objectivepgp_BN_abs_is_word BORINGSSL_PREFIX %+ __objectivepgp_BN_abs_is_word
%xdefine _objectivepgp_BN_add BORINGSSL_PREFIX %+ __objectivepgp_BN_add
%xdefine _objectivepgp_BN_add_word BORINGSSL_PREFIX %+ __objectivepgp_BN_add_word
%xdefine _objectivepgp_BN_bin2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_bin2bn
%xdefine _objectivepgp_BN_bn2bin BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2bin
%xdefine _objectivepgp_BN_bn2bin_padded BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2bin_padded
%xdefine _objectivepgp_BN_bn2le_padded BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2le_padded
%xdefine _objectivepgp_BN_clear BORINGSSL_PREFIX %+ __objectivepgp_BN_clear
%xdefine _objectivepgp_BN_clear_bit BORINGSSL_PREFIX %+ __objectivepgp_BN_clear_bit
%xdefine _objectivepgp_BN_clear_free BORINGSSL_PREFIX %+ __objectivepgp_BN_clear_free
%xdefine _objectivepgp_BN_cmp BORINGSSL_PREFIX %+ __objectivepgp_BN_cmp
%xdefine _objectivepgp_BN_cmp_word BORINGSSL_PREFIX %+ __objectivepgp_BN_cmp_word
%xdefine _objectivepgp_BN_copy BORINGSSL_PREFIX %+ __objectivepgp_BN_copy
%xdefine _objectivepgp_BN_count_low_zero_bits BORINGSSL_PREFIX %+ __objectivepgp_BN_count_low_zero_bits
%xdefine _objectivepgp_BN_div BORINGSSL_PREFIX %+ __objectivepgp_BN_div
%xdefine _objectivepgp_BN_div_word BORINGSSL_PREFIX %+ __objectivepgp_BN_div_word
%xdefine _objectivepgp_BN_dup BORINGSSL_PREFIX %+ __objectivepgp_BN_dup
%xdefine _objectivepgp_BN_enhanced_miller_rabin_primality_test BORINGSSL_PREFIX %+ __objectivepgp_BN_enhanced_miller_rabin_primality_test
%xdefine _objectivepgp_BN_equal_consttime BORINGSSL_PREFIX %+ __objectivepgp_BN_equal_consttime
%xdefine _objectivepgp_BN_exp BORINGSSL_PREFIX %+ __objectivepgp_BN_exp
%xdefine _objectivepgp_BN_free BORINGSSL_PREFIX %+ __objectivepgp_BN_free
%xdefine _objectivepgp_BN_from_montgomery BORINGSSL_PREFIX %+ __objectivepgp_BN_from_montgomery
%xdefine _objectivepgp_BN_gcd BORINGSSL_PREFIX %+ __objectivepgp_BN_gcd
%xdefine _objectivepgp_BN_generate_prime_ex BORINGSSL_PREFIX %+ __objectivepgp_BN_generate_prime_ex
%xdefine _objectivepgp_BN_get_u64 BORINGSSL_PREFIX %+ __objectivepgp_BN_get_u64
%xdefine _objectivepgp_BN_get_word BORINGSSL_PREFIX %+ __objectivepgp_BN_get_word
%xdefine _objectivepgp_BN_init BORINGSSL_PREFIX %+ __objectivepgp_BN_init
%xdefine _objectivepgp_BN_is_bit_set BORINGSSL_PREFIX %+ __objectivepgp_BN_is_bit_set
%xdefine _objectivepgp_BN_is_negative BORINGSSL_PREFIX %+ __objectivepgp_BN_is_negative
%xdefine _objectivepgp_BN_is_odd BORINGSSL_PREFIX %+ __objectivepgp_BN_is_odd
%xdefine _objectivepgp_BN_is_one BORINGSSL_PREFIX %+ __objectivepgp_BN_is_one
%xdefine _objectivepgp_BN_is_pow2 BORINGSSL_PREFIX %+ __objectivepgp_BN_is_pow2
%xdefine _objectivepgp_BN_is_prime_ex BORINGSSL_PREFIX %+ __objectivepgp_BN_is_prime_ex
%xdefine _objectivepgp_BN_is_prime_fasttest_ex BORINGSSL_PREFIX %+ __objectivepgp_BN_is_prime_fasttest_ex
%xdefine _objectivepgp_BN_is_word BORINGSSL_PREFIX %+ __objectivepgp_BN_is_word
%xdefine _objectivepgp_BN_is_zero BORINGSSL_PREFIX %+ __objectivepgp_BN_is_zero
%xdefine _objectivepgp_BN_le2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_le2bn
%xdefine _objectivepgp_BN_lshift BORINGSSL_PREFIX %+ __objectivepgp_BN_lshift
%xdefine _objectivepgp_BN_lshift1 BORINGSSL_PREFIX %+ __objectivepgp_BN_lshift1
%xdefine _objectivepgp_BN_mask_bits BORINGSSL_PREFIX %+ __objectivepgp_BN_mask_bits
%xdefine _objectivepgp_BN_mod_add BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_add
%xdefine _objectivepgp_BN_mod_add_quick BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_add_quick
%xdefine _objectivepgp_BN_mod_exp BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp
%xdefine _objectivepgp_BN_mod_exp2_mont BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp2_mont
%xdefine _objectivepgp_BN_mod_exp_mont BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont
%xdefine _objectivepgp_BN_mod_exp_mont_consttime BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont_consttime
%xdefine _objectivepgp_BN_mod_exp_mont_word BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_exp_mont_word
%xdefine _objectivepgp_BN_mod_inverse BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse
%xdefine _objectivepgp_BN_mod_inverse_blinded BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse_blinded
%xdefine _objectivepgp_BN_mod_inverse_odd BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_inverse_odd
%xdefine _objectivepgp_BN_mod_lshift BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift
%xdefine _objectivepgp_BN_mod_lshift1 BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift1
%xdefine _objectivepgp_BN_mod_lshift1_quick BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift1_quick
%xdefine _objectivepgp_BN_mod_lshift_quick BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_lshift_quick
%xdefine _objectivepgp_BN_mod_mul BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_mul
%xdefine _objectivepgp_BN_mod_mul_montgomery BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_mul_montgomery
%xdefine _objectivepgp_BN_mod_pow2 BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_pow2
%xdefine _objectivepgp_BN_mod_sqr BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sqr
%xdefine _objectivepgp_BN_mod_sqrt BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sqrt
%xdefine _objectivepgp_BN_mod_sub BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sub
%xdefine _objectivepgp_BN_mod_sub_quick BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_sub_quick
%xdefine _objectivepgp_BN_mod_word BORINGSSL_PREFIX %+ __objectivepgp_BN_mod_word
%xdefine _objectivepgp_BN_mul BORINGSSL_PREFIX %+ __objectivepgp_BN_mul
%xdefine _objectivepgp_BN_mul_word BORINGSSL_PREFIX %+ __objectivepgp_BN_mul_word
%xdefine _objectivepgp_BN_new BORINGSSL_PREFIX %+ __objectivepgp_BN_new
%xdefine _objectivepgp_BN_nnmod BORINGSSL_PREFIX %+ __objectivepgp_BN_nnmod
%xdefine _objectivepgp_BN_nnmod_pow2 BORINGSSL_PREFIX %+ __objectivepgp_BN_nnmod_pow2
%xdefine _objectivepgp_BN_num_bits BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bits
%xdefine _objectivepgp_BN_num_bits_word BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bits_word
%xdefine _objectivepgp_BN_num_bytes BORINGSSL_PREFIX %+ __objectivepgp_BN_num_bytes
%xdefine _objectivepgp_BN_one BORINGSSL_PREFIX %+ __objectivepgp_BN_one
%xdefine _objectivepgp_BN_primality_test BORINGSSL_PREFIX %+ __objectivepgp_BN_primality_test
%xdefine _objectivepgp_BN_pseudo_rand BORINGSSL_PREFIX %+ __objectivepgp_BN_pseudo_rand
%xdefine _objectivepgp_BN_pseudo_rand_range BORINGSSL_PREFIX %+ __objectivepgp_BN_pseudo_rand_range
%xdefine _objectivepgp_BN_rand BORINGSSL_PREFIX %+ __objectivepgp_BN_rand
%xdefine _objectivepgp_BN_rand_range BORINGSSL_PREFIX %+ __objectivepgp_BN_rand_range
%xdefine _objectivepgp_BN_rand_range_ex BORINGSSL_PREFIX %+ __objectivepgp_BN_rand_range_ex
%xdefine _objectivepgp_BN_rshift BORINGSSL_PREFIX %+ __objectivepgp_BN_rshift
%xdefine _objectivepgp_BN_rshift1 BORINGSSL_PREFIX %+ __objectivepgp_BN_rshift1
%xdefine _objectivepgp_BN_set_bit BORINGSSL_PREFIX %+ __objectivepgp_BN_set_bit
%xdefine _objectivepgp_BN_set_negative BORINGSSL_PREFIX %+ __objectivepgp_BN_set_negative
%xdefine _objectivepgp_BN_set_u64 BORINGSSL_PREFIX %+ __objectivepgp_BN_set_u64
%xdefine _objectivepgp_BN_set_word BORINGSSL_PREFIX %+ __objectivepgp_BN_set_word
%xdefine _objectivepgp_BN_sqr BORINGSSL_PREFIX %+ __objectivepgp_BN_sqr
%xdefine _objectivepgp_BN_sqrt BORINGSSL_PREFIX %+ __objectivepgp_BN_sqrt
%xdefine _objectivepgp_BN_sub BORINGSSL_PREFIX %+ __objectivepgp_BN_sub
%xdefine _objectivepgp_BN_sub_word BORINGSSL_PREFIX %+ __objectivepgp_BN_sub_word
%xdefine _objectivepgp_BN_to_montgomery BORINGSSL_PREFIX %+ __objectivepgp_BN_to_montgomery
%xdefine _objectivepgp_BN_uadd BORINGSSL_PREFIX %+ __objectivepgp_BN_uadd
%xdefine _objectivepgp_BN_ucmp BORINGSSL_PREFIX %+ __objectivepgp_BN_ucmp
%xdefine _objectivepgp_BN_usub BORINGSSL_PREFIX %+ __objectivepgp_BN_usub
%xdefine _objectivepgp_BN_value_one BORINGSSL_PREFIX %+ __objectivepgp_BN_value_one
%xdefine _objectivepgp_BN_zero BORINGSSL_PREFIX %+ __objectivepgp_BN_zero
%xdefine _objectivepgp_BORINGSSL_self_test BORINGSSL_PREFIX %+ __objectivepgp_BORINGSSL_self_test
%xdefine _objectivepgp_CRYPTO_POLYVAL_finish BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_finish
%xdefine _objectivepgp_CRYPTO_POLYVAL_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_init
%xdefine _objectivepgp_CRYPTO_POLYVAL_update_blocks BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_POLYVAL_update_blocks
%xdefine _objectivepgp_CRYPTO_cbc128_decrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cbc128_decrypt
%xdefine _objectivepgp_CRYPTO_cbc128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cbc128_encrypt
%xdefine _objectivepgp_CRYPTO_cfb128_1_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_1_encrypt
%xdefine _objectivepgp_CRYPTO_cfb128_8_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_8_encrypt
%xdefine _objectivepgp_CRYPTO_cfb128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cfb128_encrypt
%xdefine _objectivepgp_CRYPTO_ctr128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ctr128_encrypt
%xdefine _objectivepgp_CRYPTO_ctr128_encrypt_ctr32 BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ctr128_encrypt_ctr32
%xdefine _objectivepgp_CRYPTO_gcm128_aad BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_aad
%xdefine _objectivepgp_CRYPTO_gcm128_decrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_decrypt
%xdefine _objectivepgp_CRYPTO_gcm128_decrypt_ctr32 BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_decrypt_ctr32
%xdefine _objectivepgp_CRYPTO_gcm128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_encrypt
%xdefine _objectivepgp_CRYPTO_gcm128_encrypt_ctr32 BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_encrypt_ctr32
%xdefine _objectivepgp_CRYPTO_gcm128_finish BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_finish
%xdefine _objectivepgp_CRYPTO_gcm128_init_key BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_init_key
%xdefine _objectivepgp_CRYPTO_gcm128_setiv BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_setiv
%xdefine _objectivepgp_CRYPTO_gcm128_tag BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_gcm128_tag
%xdefine _objectivepgp_CRYPTO_ghash_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ghash_init
%xdefine _objectivepgp_CRYPTO_ofb128_encrypt BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_ofb128_encrypt
%xdefine _objectivepgp_CRYPTO_sysrand BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_sysrand
%xdefine _objectivepgp_CRYPTO_tls1_prf BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_tls1_prf
%xdefine _objectivepgp_CTR_DRBG_clear BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_clear
%xdefine _objectivepgp_CTR_DRBG_generate BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_generate
%xdefine _objectivepgp_CTR_DRBG_init BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_init
%xdefine _objectivepgp_CTR_DRBG_reseed BORINGSSL_PREFIX %+ __objectivepgp_CTR_DRBG_reseed
%xdefine _objectivepgp_DES_decrypt3 BORINGSSL_PREFIX %+ __objectivepgp_DES_decrypt3
%xdefine _objectivepgp_DES_ecb3_encrypt BORINGSSL_PREFIX %+ __objectivepgp_DES_ecb3_encrypt
%xdefine _objectivepgp_DES_ecb_encrypt BORINGSSL_PREFIX %+ __objectivepgp_DES_ecb_encrypt
%xdefine _objectivepgp_DES_ede2_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_DES_ede2_cbc_encrypt
%xdefine _objectivepgp_DES_ede3_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_DES_ede3_cbc_encrypt
%xdefine _objectivepgp_DES_encrypt3 BORINGSSL_PREFIX %+ __objectivepgp_DES_encrypt3
%xdefine _objectivepgp_DES_ncbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_DES_ncbc_encrypt
%xdefine _objectivepgp_DES_set_key BORINGSSL_PREFIX %+ __objectivepgp_DES_set_key
%xdefine _objectivepgp_DES_set_key_unchecked BORINGSSL_PREFIX %+ __objectivepgp_DES_set_key_unchecked
%xdefine _objectivepgp_DES_set_odd_parity BORINGSSL_PREFIX %+ __objectivepgp_DES_set_odd_parity
%xdefine _objectivepgp_ECDH_compute_key_fips BORINGSSL_PREFIX %+ __objectivepgp_ECDH_compute_key_fips
%xdefine _objectivepgp_ECDSA_SIG_free BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_free
%xdefine _objectivepgp_ECDSA_SIG_get0 BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_get0
%xdefine _objectivepgp_ECDSA_SIG_new BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_new
%xdefine _objectivepgp_ECDSA_SIG_set0 BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_set0
%xdefine _objectivepgp_ECDSA_do_sign BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_do_sign
%xdefine _objectivepgp_ECDSA_do_verify BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_do_verify
%xdefine _objectivepgp_EC_GFp_mont_method BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_mont_method
%xdefine _objectivepgp_EC_GFp_nistp224_method BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistp224_method
%xdefine _objectivepgp_EC_GFp_nistp256_method BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistp256_method
%xdefine _objectivepgp_EC_GFp_nistz256_method BORINGSSL_PREFIX %+ __objectivepgp_EC_GFp_nistz256_method
%xdefine _objectivepgp_EC_GROUP_cmp BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_cmp
%xdefine _objectivepgp_EC_GROUP_dup BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_dup
%xdefine _objectivepgp_EC_GROUP_free BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_free
%xdefine _objectivepgp_EC_GROUP_get0_generator BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get0_generator
%xdefine _objectivepgp_EC_GROUP_get0_order BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get0_order
%xdefine _objectivepgp_EC_GROUP_get_cofactor BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_cofactor
%xdefine _objectivepgp_EC_GROUP_get_curve_GFp BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_curve_GFp
%xdefine _objectivepgp_EC_GROUP_get_curve_name BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_curve_name
%xdefine _objectivepgp_EC_GROUP_get_degree BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_degree
%xdefine _objectivepgp_EC_GROUP_get_order BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_get_order
%xdefine _objectivepgp_EC_GROUP_method_of BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_method_of
%xdefine _objectivepgp_EC_GROUP_new_by_curve_name BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_new_by_curve_name
%xdefine _objectivepgp_EC_GROUP_new_curve_GFp BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_new_curve_GFp
%xdefine _objectivepgp_EC_GROUP_order_bits BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_order_bits
%xdefine _objectivepgp_EC_GROUP_set_asn1_flag BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_asn1_flag
%xdefine _objectivepgp_EC_GROUP_set_generator BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_generator
%xdefine _objectivepgp_EC_GROUP_set_point_conversion_form BORINGSSL_PREFIX %+ __objectivepgp_EC_GROUP_set_point_conversion_form
%xdefine _objectivepgp_EC_KEY_check_fips BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_check_fips
%xdefine _objectivepgp_EC_KEY_check_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_check_key
%xdefine _objectivepgp_EC_KEY_dup BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_dup
%xdefine _objectivepgp_EC_KEY_free BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_free
%xdefine _objectivepgp_EC_KEY_generate_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_generate_key
%xdefine _objectivepgp_EC_KEY_generate_key_fips BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_generate_key_fips
%xdefine _objectivepgp_EC_KEY_get0_group BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_group
%xdefine _objectivepgp_EC_KEY_get0_private_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_private_key
%xdefine _objectivepgp_EC_KEY_get0_public_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get0_public_key
%xdefine _objectivepgp_EC_KEY_get_conv_form BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_conv_form
%xdefine _objectivepgp_EC_KEY_get_enc_flags BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_enc_flags
%xdefine _objectivepgp_EC_KEY_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_ex_data
%xdefine _objectivepgp_EC_KEY_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_get_ex_new_index
%xdefine _objectivepgp_EC_KEY_is_opaque BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_is_opaque
%xdefine _objectivepgp_EC_KEY_key2buf BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_key2buf
%xdefine _objectivepgp_EC_KEY_new BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new
%xdefine _objectivepgp_EC_KEY_new_by_curve_name BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new_by_curve_name
%xdefine _objectivepgp_EC_KEY_new_method BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_new_method
%xdefine _objectivepgp_EC_KEY_set_asn1_flag BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_asn1_flag
%xdefine _objectivepgp_EC_KEY_set_conv_form BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_conv_form
%xdefine _objectivepgp_EC_KEY_set_enc_flags BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_enc_flags
%xdefine _objectivepgp_EC_KEY_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_ex_data
%xdefine _objectivepgp_EC_KEY_set_group BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_group
%xdefine _objectivepgp_EC_KEY_set_private_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_private_key
%xdefine _objectivepgp_EC_KEY_set_public_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_public_key
%xdefine _objectivepgp_EC_KEY_set_public_key_affine_coordinates BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_set_public_key_affine_coordinates
%xdefine _objectivepgp_EC_KEY_up_ref BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_up_ref
%xdefine _objectivepgp_EC_METHOD_get_field_type BORINGSSL_PREFIX %+ __objectivepgp_EC_METHOD_get_field_type
%xdefine _objectivepgp_EC_POINT_add BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_add
%xdefine _objectivepgp_EC_POINT_clear_free BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_clear_free
%xdefine _objectivepgp_EC_POINT_cmp BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_cmp
%xdefine _objectivepgp_EC_POINT_copy BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_copy
%xdefine _objectivepgp_EC_POINT_dbl BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_dbl
%xdefine _objectivepgp_EC_POINT_dup BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_dup
%xdefine _objectivepgp_EC_POINT_free BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_free
%xdefine _objectivepgp_EC_POINT_get_affine_coordinates_GFp BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_get_affine_coordinates_GFp
%xdefine _objectivepgp_EC_POINT_invert BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_invert
%xdefine _objectivepgp_EC_POINT_is_at_infinity BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_is_at_infinity
%xdefine _objectivepgp_EC_POINT_is_on_curve BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_is_on_curve
%xdefine _objectivepgp_EC_POINT_mul BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_mul
%xdefine _objectivepgp_EC_POINT_new BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_new
%xdefine _objectivepgp_EC_POINT_oct2point BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_oct2point
%xdefine _objectivepgp_EC_POINT_point2oct BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_point2oct
%xdefine _objectivepgp_EC_POINT_set_affine_coordinates_GFp BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_affine_coordinates_GFp
%xdefine _objectivepgp_EC_POINT_set_compressed_coordinates_GFp BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_compressed_coordinates_GFp
%xdefine _objectivepgp_EC_POINT_set_to_infinity BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_set_to_infinity
%xdefine _objectivepgp_EC_curve_nid2nist BORINGSSL_PREFIX %+ __objectivepgp_EC_curve_nid2nist
%xdefine _objectivepgp_EC_curve_nist2nid BORINGSSL_PREFIX %+ __objectivepgp_EC_curve_nist2nid
%xdefine _objectivepgp_EC_get_builtin_curves BORINGSSL_PREFIX %+ __objectivepgp_EC_get_builtin_curves
%xdefine _objectivepgp_EVP_AEAD_CTX_aead BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_aead
%xdefine _objectivepgp_EVP_AEAD_CTX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_cleanup
%xdefine _objectivepgp_EVP_AEAD_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_free
%xdefine _objectivepgp_EVP_AEAD_CTX_get_iv BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_get_iv
%xdefine _objectivepgp_EVP_AEAD_CTX_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_init
%xdefine _objectivepgp_EVP_AEAD_CTX_init_with_direction BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_init_with_direction
%xdefine _objectivepgp_EVP_AEAD_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_new
%xdefine _objectivepgp_EVP_AEAD_CTX_open BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_open
%xdefine _objectivepgp_EVP_AEAD_CTX_open_gather BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_open_gather
%xdefine _objectivepgp_EVP_AEAD_CTX_seal BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_seal
%xdefine _objectivepgp_EVP_AEAD_CTX_seal_scatter BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_seal_scatter
%xdefine _objectivepgp_EVP_AEAD_CTX_tag_len BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_tag_len
%xdefine _objectivepgp_EVP_AEAD_CTX_zero BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_CTX_zero
%xdefine _objectivepgp_EVP_AEAD_key_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_key_length
%xdefine _objectivepgp_EVP_AEAD_max_overhead BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_max_overhead
%xdefine _objectivepgp_EVP_AEAD_max_tag_len BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_max_tag_len
%xdefine _objectivepgp_EVP_AEAD_nonce_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_AEAD_nonce_length
%xdefine _objectivepgp_EVP_CIPHER_CTX_block_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_block_size
%xdefine _objectivepgp_EVP_CIPHER_CTX_cipher BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_cipher
%xdefine _objectivepgp_EVP_CIPHER_CTX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_cleanup
%xdefine _objectivepgp_EVP_CIPHER_CTX_copy BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_copy
%xdefine _objectivepgp_EVP_CIPHER_CTX_ctrl BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_ctrl
%xdefine _objectivepgp_EVP_CIPHER_CTX_encrypting BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_encrypting
%xdefine _objectivepgp_EVP_CIPHER_CTX_flags BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_flags
%xdefine _objectivepgp_EVP_CIPHER_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_free
%xdefine _objectivepgp_EVP_CIPHER_CTX_get_app_data BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_get_app_data
%xdefine _objectivepgp_EVP_CIPHER_CTX_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_init
%xdefine _objectivepgp_EVP_CIPHER_CTX_iv_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_iv_length
%xdefine _objectivepgp_EVP_CIPHER_CTX_key_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_key_length
%xdefine _objectivepgp_EVP_CIPHER_CTX_mode BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_mode
%xdefine _objectivepgp_EVP_CIPHER_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_new
%xdefine _objectivepgp_EVP_CIPHER_CTX_nid BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_nid
%xdefine _objectivepgp_EVP_CIPHER_CTX_reset BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_reset
%xdefine _objectivepgp_EVP_CIPHER_CTX_set_app_data BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_app_data
%xdefine _objectivepgp_EVP_CIPHER_CTX_set_flags BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_flags
%xdefine _objectivepgp_EVP_CIPHER_CTX_set_key_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_key_length
%xdefine _objectivepgp_EVP_CIPHER_CTX_set_padding BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_CTX_set_padding
%xdefine _objectivepgp_EVP_CIPHER_block_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_block_size
%xdefine _objectivepgp_EVP_CIPHER_flags BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_flags
%xdefine _objectivepgp_EVP_CIPHER_iv_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_iv_length
%xdefine _objectivepgp_EVP_CIPHER_key_length BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_key_length
%xdefine _objectivepgp_EVP_CIPHER_mode BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_mode
%xdefine _objectivepgp_EVP_CIPHER_nid BORINGSSL_PREFIX %+ __objectivepgp_EVP_CIPHER_nid
%xdefine _objectivepgp_EVP_Cipher BORINGSSL_PREFIX %+ __objectivepgp_EVP_Cipher
%xdefine _objectivepgp_EVP_CipherFinal_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherFinal_ex
%xdefine _objectivepgp_EVP_CipherInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherInit
%xdefine _objectivepgp_EVP_CipherInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherInit_ex
%xdefine _objectivepgp_EVP_CipherUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_CipherUpdate
%xdefine _objectivepgp_EVP_DecryptFinal_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptFinal_ex
%xdefine _objectivepgp_EVP_DecryptInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptInit
%xdefine _objectivepgp_EVP_DecryptInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptInit_ex
%xdefine _objectivepgp_EVP_DecryptUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecryptUpdate
%xdefine _objectivepgp_EVP_Digest BORINGSSL_PREFIX %+ __objectivepgp_EVP_Digest
%xdefine _objectivepgp_EVP_DigestFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinal
%xdefine _objectivepgp_EVP_DigestFinalXOF BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinalXOF
%xdefine _objectivepgp_EVP_DigestFinal_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestFinal_ex
%xdefine _objectivepgp_EVP_DigestInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestInit
%xdefine _objectivepgp_EVP_DigestInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestInit_ex
%xdefine _objectivepgp_EVP_DigestUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestUpdate
%xdefine _objectivepgp_EVP_EncryptFinal_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptFinal_ex
%xdefine _objectivepgp_EVP_EncryptInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptInit
%xdefine _objectivepgp_EVP_EncryptInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptInit_ex
%xdefine _objectivepgp_EVP_EncryptUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncryptUpdate
%xdefine _objectivepgp_EVP_MD_CTX_block_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_block_size
%xdefine _objectivepgp_EVP_MD_CTX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_cleanup
%xdefine _objectivepgp_EVP_MD_CTX_copy BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_copy
%xdefine _objectivepgp_EVP_MD_CTX_copy_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_copy_ex
%xdefine _objectivepgp_EVP_MD_CTX_create BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_create
%xdefine _objectivepgp_EVP_MD_CTX_destroy BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_destroy
%xdefine _objectivepgp_EVP_MD_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_free
%xdefine _objectivepgp_EVP_MD_CTX_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_init
%xdefine _objectivepgp_EVP_MD_CTX_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_md
%xdefine _objectivepgp_EVP_MD_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_new
%xdefine _objectivepgp_EVP_MD_CTX_reset BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_reset
%xdefine _objectivepgp_EVP_MD_CTX_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_size
%xdefine _objectivepgp_EVP_MD_CTX_type BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_CTX_type
%xdefine _objectivepgp_EVP_MD_block_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_block_size
%xdefine _objectivepgp_EVP_MD_flags BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_flags
%xdefine _objectivepgp_EVP_MD_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_size
%xdefine _objectivepgp_EVP_MD_type BORINGSSL_PREFIX %+ __objectivepgp_EVP_MD_type
%xdefine _objectivepgp_EVP_add_cipher_alias BORINGSSL_PREFIX %+ __objectivepgp_EVP_add_cipher_alias
%xdefine _objectivepgp_EVP_add_digest BORINGSSL_PREFIX %+ __objectivepgp_EVP_add_digest
%xdefine _objectivepgp_EVP_aead_aes_128_gcm BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm
%xdefine _objectivepgp_EVP_aead_aes_128_gcm_tls12 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_tls12
%xdefine _objectivepgp_EVP_aead_aes_128_gcm_tls13 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_tls13
%xdefine _objectivepgp_EVP_aead_aes_256_gcm BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm
%xdefine _objectivepgp_EVP_aead_aes_256_gcm_tls12 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_tls12
%xdefine _objectivepgp_EVP_aead_aes_256_gcm_tls13 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_tls13
%xdefine _objectivepgp_EVP_aes_128_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_cbc
%xdefine _objectivepgp_EVP_aes_128_ctr BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ctr
%xdefine _objectivepgp_EVP_aes_128_ecb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ecb
%xdefine _objectivepgp_EVP_aes_128_gcm BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_gcm
%xdefine _objectivepgp_EVP_aes_128_ofb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_128_ofb
%xdefine _objectivepgp_EVP_aes_192_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_cbc
%xdefine _objectivepgp_EVP_aes_192_ctr BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ctr
%xdefine _objectivepgp_EVP_aes_192_ecb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ecb
%xdefine _objectivepgp_EVP_aes_192_gcm BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_gcm
%xdefine _objectivepgp_EVP_aes_192_ofb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_192_ofb
%xdefine _objectivepgp_EVP_aes_256_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_cbc
%xdefine _objectivepgp_EVP_aes_256_ctr BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ctr
%xdefine _objectivepgp_EVP_aes_256_ecb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ecb
%xdefine _objectivepgp_EVP_aes_256_gcm BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_gcm
%xdefine _objectivepgp_EVP_aes_256_ofb BORINGSSL_PREFIX %+ __objectivepgp_EVP_aes_256_ofb
%xdefine _objectivepgp_EVP_des_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_cbc
%xdefine _objectivepgp_EVP_des_ecb BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ecb
%xdefine _objectivepgp_EVP_des_ede BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede
%xdefine _objectivepgp_EVP_des_ede3 BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3
%xdefine _objectivepgp_EVP_des_ede3_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3_cbc
%xdefine _objectivepgp_EVP_des_ede3_ecb BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede3_ecb
%xdefine _objectivepgp_EVP_des_ede_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_des_ede_cbc
%xdefine _objectivepgp_EVP_has_aes_hardware BORINGSSL_PREFIX %+ __objectivepgp_EVP_has_aes_hardware
%xdefine _objectivepgp_EVP_md4 BORINGSSL_PREFIX %+ __objectivepgp_EVP_md4
%xdefine _objectivepgp_EVP_md5 BORINGSSL_PREFIX %+ __objectivepgp_EVP_md5
%xdefine _objectivepgp_EVP_md5_sha1 BORINGSSL_PREFIX %+ __objectivepgp_EVP_md5_sha1
%xdefine _objectivepgp_EVP_sha1 BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha1
%xdefine _objectivepgp_EVP_sha224 BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha224
%xdefine _objectivepgp_EVP_sha256 BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha256
%xdefine _objectivepgp_EVP_sha384 BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha384
%xdefine _objectivepgp_EVP_sha512 BORINGSSL_PREFIX %+ __objectivepgp_EVP_sha512
%xdefine _objectivepgp_HMAC BORINGSSL_PREFIX %+ __objectivepgp_HMAC
%xdefine _objectivepgp_HMAC_CTX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_cleanup
%xdefine _objectivepgp_HMAC_CTX_copy BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_copy
%xdefine _objectivepgp_HMAC_CTX_copy_ex BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_copy_ex
%xdefine _objectivepgp_HMAC_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_free
%xdefine _objectivepgp_HMAC_CTX_init BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_init
%xdefine _objectivepgp_HMAC_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_new
%xdefine _objectivepgp_HMAC_CTX_reset BORINGSSL_PREFIX %+ __objectivepgp_HMAC_CTX_reset
%xdefine _objectivepgp_HMAC_Final BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Final
%xdefine _objectivepgp_HMAC_Init BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Init
%xdefine _objectivepgp_HMAC_Init_ex BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Init_ex
%xdefine _objectivepgp_HMAC_Update BORINGSSL_PREFIX %+ __objectivepgp_HMAC_Update
%xdefine _objectivepgp_HMAC_size BORINGSSL_PREFIX %+ __objectivepgp_HMAC_size
%xdefine _objectivepgp_MD4 BORINGSSL_PREFIX %+ __objectivepgp_MD4
%xdefine _objectivepgp_MD4_Final BORINGSSL_PREFIX %+ __objectivepgp_MD4_Final
%xdefine _objectivepgp_MD4_Init BORINGSSL_PREFIX %+ __objectivepgp_MD4_Init
%xdefine _objectivepgp_MD4_Transform BORINGSSL_PREFIX %+ __objectivepgp_MD4_Transform
%xdefine _objectivepgp_MD4_Update BORINGSSL_PREFIX %+ __objectivepgp_MD4_Update
%xdefine _objectivepgp_MD5 BORINGSSL_PREFIX %+ __objectivepgp_MD5
%xdefine _objectivepgp_MD5_Final BORINGSSL_PREFIX %+ __objectivepgp_MD5_Final
%xdefine _objectivepgp_MD5_Init BORINGSSL_PREFIX %+ __objectivepgp_MD5_Init
%xdefine _objectivepgp_MD5_Transform BORINGSSL_PREFIX %+ __objectivepgp_MD5_Transform
%xdefine _objectivepgp_MD5_Update BORINGSSL_PREFIX %+ __objectivepgp_MD5_Update
%xdefine _objectivepgp_OPENSSL_built_in_curves BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_built_in_curves
%xdefine _objectivepgp_RAND_bytes BORINGSSL_PREFIX %+ __objectivepgp_RAND_bytes
%xdefine _objectivepgp_RAND_bytes_with_additional_data BORINGSSL_PREFIX %+ __objectivepgp_RAND_bytes_with_additional_data
%xdefine _objectivepgp_RAND_pseudo_bytes BORINGSSL_PREFIX %+ __objectivepgp_RAND_pseudo_bytes
%xdefine _objectivepgp_RAND_set_urandom_fd BORINGSSL_PREFIX %+ __objectivepgp_RAND_set_urandom_fd
%xdefine _objectivepgp_RSAZ_1024_mod_exp_avx2 BORINGSSL_PREFIX %+ __objectivepgp_RSAZ_1024_mod_exp_avx2
%xdefine _objectivepgp_RSA_add_pkcs1_prefix BORINGSSL_PREFIX %+ __objectivepgp_RSA_add_pkcs1_prefix
%xdefine _objectivepgp_RSA_bits BORINGSSL_PREFIX %+ __objectivepgp_RSA_bits
%xdefine _objectivepgp_RSA_blinding_on BORINGSSL_PREFIX %+ __objectivepgp_RSA_blinding_on
%xdefine _objectivepgp_RSA_check_fips BORINGSSL_PREFIX %+ __objectivepgp_RSA_check_fips
%xdefine _objectivepgp_RSA_check_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_check_key
%xdefine _objectivepgp_RSA_decrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_decrypt
%xdefine _objectivepgp_RSA_default_method BORINGSSL_PREFIX %+ __objectivepgp_RSA_default_method
%xdefine _objectivepgp_RSA_encrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_encrypt
%xdefine _objectivepgp_RSA_flags BORINGSSL_PREFIX %+ __objectivepgp_RSA_flags
%xdefine _objectivepgp_RSA_free BORINGSSL_PREFIX %+ __objectivepgp_RSA_free
%xdefine _objectivepgp_RSA_generate_key_ex BORINGSSL_PREFIX %+ __objectivepgp_RSA_generate_key_ex
%xdefine _objectivepgp_RSA_generate_key_fips BORINGSSL_PREFIX %+ __objectivepgp_RSA_generate_key_fips
%xdefine _objectivepgp_RSA_get0_crt_params BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_crt_params
%xdefine _objectivepgp_RSA_get0_factors BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_factors
%xdefine _objectivepgp_RSA_get0_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_get0_key
%xdefine _objectivepgp_RSA_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_RSA_get_ex_data
%xdefine _objectivepgp_RSA_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_RSA_get_ex_new_index
%xdefine _objectivepgp_RSA_is_opaque BORINGSSL_PREFIX %+ __objectivepgp_RSA_is_opaque
%xdefine _objectivepgp_RSA_new BORINGSSL_PREFIX %+ __objectivepgp_RSA_new
%xdefine _objectivepgp_RSA_new_method BORINGSSL_PREFIX %+ __objectivepgp_RSA_new_method
%xdefine _objectivepgp_RSA_padding_add_PKCS1_OAEP_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_OAEP_mgf1
%xdefine _objectivepgp_RSA_padding_add_PKCS1_PSS_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_PSS_mgf1
%xdefine _objectivepgp_RSA_padding_add_PKCS1_type_1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_type_1
%xdefine _objectivepgp_RSA_padding_add_PKCS1_type_2 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_PKCS1_type_2
%xdefine _objectivepgp_RSA_padding_add_none BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_add_none
%xdefine _objectivepgp_RSA_padding_check_PKCS1_OAEP_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_OAEP_mgf1
%xdefine _objectivepgp_RSA_padding_check_PKCS1_type_1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_type_1
%xdefine _objectivepgp_RSA_padding_check_PKCS1_type_2 BORINGSSL_PREFIX %+ __objectivepgp_RSA_padding_check_PKCS1_type_2
%xdefine _objectivepgp_RSA_private_decrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_decrypt
%xdefine _objectivepgp_RSA_private_encrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_encrypt
%xdefine _objectivepgp_RSA_private_transform BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_transform
%xdefine _objectivepgp_RSA_public_decrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_decrypt
%xdefine _objectivepgp_RSA_public_encrypt BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_encrypt
%xdefine _objectivepgp_RSA_set0_crt_params BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_crt_params
%xdefine _objectivepgp_RSA_set0_factors BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_factors
%xdefine _objectivepgp_RSA_set0_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_set0_key
%xdefine _objectivepgp_RSA_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_RSA_set_ex_data
%xdefine _objectivepgp_RSA_sign BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign
%xdefine _objectivepgp_RSA_sign_pss_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign_pss_mgf1
%xdefine _objectivepgp_RSA_sign_raw BORINGSSL_PREFIX %+ __objectivepgp_RSA_sign_raw
%xdefine _objectivepgp_RSA_size BORINGSSL_PREFIX %+ __objectivepgp_RSA_size
%xdefine _objectivepgp_RSA_up_ref BORINGSSL_PREFIX %+ __objectivepgp_RSA_up_ref
%xdefine _objectivepgp_RSA_verify BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify
%xdefine _objectivepgp_RSA_verify_PKCS1_PSS_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_PKCS1_PSS_mgf1
%xdefine _objectivepgp_RSA_verify_pss_mgf1 BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_pss_mgf1
%xdefine _objectivepgp_RSA_verify_raw BORINGSSL_PREFIX %+ __objectivepgp_RSA_verify_raw
%xdefine _objectivepgp_SHA1 BORINGSSL_PREFIX %+ __objectivepgp_SHA1
%xdefine _objectivepgp_SHA1_Final BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Final
%xdefine _objectivepgp_SHA1_Init BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Init
%xdefine _objectivepgp_SHA1_Transform BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Transform
%xdefine _objectivepgp_SHA1_Update BORINGSSL_PREFIX %+ __objectivepgp_SHA1_Update
%xdefine _objectivepgp_SHA224 BORINGSSL_PREFIX %+ __objectivepgp_SHA224
%xdefine _objectivepgp_SHA224_Final BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Final
%xdefine _objectivepgp_SHA224_Init BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Init
%xdefine _objectivepgp_SHA224_Update BORINGSSL_PREFIX %+ __objectivepgp_SHA224_Update
%xdefine _objectivepgp_SHA256 BORINGSSL_PREFIX %+ __objectivepgp_SHA256
%xdefine _objectivepgp_SHA256_Final BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Final
%xdefine _objectivepgp_SHA256_Init BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Init
%xdefine _objectivepgp_SHA256_Transform BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Transform
%xdefine _objectivepgp_SHA256_TransformBlocks BORINGSSL_PREFIX %+ __objectivepgp_SHA256_TransformBlocks
%xdefine _objectivepgp_SHA256_Update BORINGSSL_PREFIX %+ __objectivepgp_SHA256_Update
%xdefine _objectivepgp_SHA384 BORINGSSL_PREFIX %+ __objectivepgp_SHA384
%xdefine _objectivepgp_SHA384_Final BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Final
%xdefine _objectivepgp_SHA384_Init BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Init
%xdefine _objectivepgp_SHA384_Update BORINGSSL_PREFIX %+ __objectivepgp_SHA384_Update
%xdefine _objectivepgp_SHA512 BORINGSSL_PREFIX %+ __objectivepgp_SHA512
%xdefine _objectivepgp_SHA512_Final BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Final
%xdefine _objectivepgp_SHA512_Init BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Init
%xdefine _objectivepgp_SHA512_Transform BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Transform
%xdefine _objectivepgp_SHA512_Update BORINGSSL_PREFIX %+ __objectivepgp_SHA512_Update
%xdefine _objectivepgp_aes_ctr_set_key BORINGSSL_PREFIX %+ __objectivepgp_aes_ctr_set_key
%xdefine _objectivepgp_bn_abs_sub_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_abs_sub_consttime
%xdefine _objectivepgp_bn_add_words BORINGSSL_PREFIX %+ __objectivepgp_bn_add_words
%xdefine _objectivepgp_bn_copy_words BORINGSSL_PREFIX %+ __objectivepgp_bn_copy_words
%xdefine _objectivepgp_bn_div_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_div_consttime
%xdefine _objectivepgp_bn_expand BORINGSSL_PREFIX %+ __objectivepgp_bn_expand
%xdefine _objectivepgp_bn_fits_in_words BORINGSSL_PREFIX %+ __objectivepgp_bn_fits_in_words
%xdefine _objectivepgp_bn_from_montgomery_small BORINGSSL_PREFIX %+ __objectivepgp_bn_from_montgomery_small
%xdefine _objectivepgp_bn_in_range_words BORINGSSL_PREFIX %+ __objectivepgp_bn_in_range_words
%xdefine _objectivepgp_bn_is_bit_set_words BORINGSSL_PREFIX %+ __objectivepgp_bn_is_bit_set_words
%xdefine _objectivepgp_bn_is_relatively_prime BORINGSSL_PREFIX %+ __objectivepgp_bn_is_relatively_prime
%xdefine _objectivepgp_bn_jacobi BORINGSSL_PREFIX %+ __objectivepgp_bn_jacobi
%xdefine _objectivepgp_bn_lcm_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_lcm_consttime
%xdefine _objectivepgp_bn_less_than_montgomery_R BORINGSSL_PREFIX %+ __objectivepgp_bn_less_than_montgomery_R
%xdefine _objectivepgp_bn_less_than_words BORINGSSL_PREFIX %+ __objectivepgp_bn_less_than_words
%xdefine _objectivepgp_bn_minimal_width BORINGSSL_PREFIX %+ __objectivepgp_bn_minimal_width
%xdefine _objectivepgp_bn_mod_add_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_add_consttime
%xdefine _objectivepgp_bn_mod_add_words BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_add_words
%xdefine _objectivepgp_bn_mod_exp_base_2_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_exp_base_2_consttime
%xdefine _objectivepgp_bn_mod_exp_mont_small BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_exp_mont_small
%xdefine _objectivepgp_bn_mod_inverse_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_consttime
%xdefine _objectivepgp_bn_mod_inverse_prime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_prime
%xdefine _objectivepgp_bn_mod_inverse_prime_mont_small BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_prime_mont_small
%xdefine _objectivepgp_bn_mod_inverse_secret_prime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_inverse_secret_prime
%xdefine _objectivepgp_bn_mod_lshift1_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_lshift1_consttime
%xdefine _objectivepgp_bn_mod_lshift_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_lshift_consttime
%xdefine _objectivepgp_bn_mod_mul_montgomery_small BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_mul_montgomery_small
%xdefine _objectivepgp_bn_mod_sub_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_sub_consttime
%xdefine _objectivepgp_bn_mod_sub_words BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_sub_words
%xdefine _objectivepgp_bn_mod_u16_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mod_u16_consttime
%xdefine _objectivepgp_bn_mont_n0 BORINGSSL_PREFIX %+ __objectivepgp_bn_mont_n0
%xdefine _objectivepgp_bn_mul_add_words BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_add_words
%xdefine _objectivepgp_bn_mul_comba4 BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_comba4
%xdefine _objectivepgp_bn_mul_comba8 BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_comba8
%xdefine _objectivepgp_bn_mul_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_consttime
%xdefine _objectivepgp_bn_mul_small BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_small
%xdefine _objectivepgp_bn_mul_words BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_words
%xdefine _objectivepgp_bn_odd_number_is_obviously_composite BORINGSSL_PREFIX %+ __objectivepgp_bn_odd_number_is_obviously_composite
%xdefine _objectivepgp_bn_one_to_montgomery BORINGSSL_PREFIX %+ __objectivepgp_bn_one_to_montgomery
%xdefine _objectivepgp_bn_rand_range_words BORINGSSL_PREFIX %+ __objectivepgp_bn_rand_range_words
%xdefine _objectivepgp_bn_rand_secret_range BORINGSSL_PREFIX %+ __objectivepgp_bn_rand_secret_range
%xdefine _objectivepgp_bn_reduce_once BORINGSSL_PREFIX %+ __objectivepgp_bn_reduce_once
%xdefine _objectivepgp_bn_reduce_once_in_place BORINGSSL_PREFIX %+ __objectivepgp_bn_reduce_once_in_place
%xdefine _objectivepgp_bn_resize_words BORINGSSL_PREFIX %+ __objectivepgp_bn_resize_words
%xdefine _objectivepgp_bn_rshift1_words BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift1_words
%xdefine _objectivepgp_bn_rshift_secret_shift BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift_secret_shift
%xdefine _objectivepgp_bn_rshift_words BORINGSSL_PREFIX %+ __objectivepgp_bn_rshift_words
%xdefine _objectivepgp_bn_select_words BORINGSSL_PREFIX %+ __objectivepgp_bn_select_words
%xdefine _objectivepgp_bn_set_minimal_width BORINGSSL_PREFIX %+ __objectivepgp_bn_set_minimal_width
%xdefine _objectivepgp_bn_set_words BORINGSSL_PREFIX %+ __objectivepgp_bn_set_words
%xdefine _objectivepgp_bn_sqr_comba4 BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_comba4
%xdefine _objectivepgp_bn_sqr_comba8 BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_comba8
%xdefine _objectivepgp_bn_sqr_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_consttime
%xdefine _objectivepgp_bn_sqr_small BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_small
%xdefine _objectivepgp_bn_sqr_words BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr_words
%xdefine _objectivepgp_bn_sub_words BORINGSSL_PREFIX %+ __objectivepgp_bn_sub_words
%xdefine _objectivepgp_bn_to_montgomery_small BORINGSSL_PREFIX %+ __objectivepgp_bn_to_montgomery_small
%xdefine _objectivepgp_bn_uadd_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_uadd_consttime
%xdefine _objectivepgp_bn_usub_consttime BORINGSSL_PREFIX %+ __objectivepgp_bn_usub_consttime
%xdefine _objectivepgp_bn_wexpand BORINGSSL_PREFIX %+ __objectivepgp_bn_wexpand
%xdefine _objectivepgp_crypto_gcm_clmul_enabled BORINGSSL_PREFIX %+ __objectivepgp_crypto_gcm_clmul_enabled
%xdefine _objectivepgp_ec_GFp_mont_add BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_add
%xdefine _objectivepgp_ec_GFp_mont_bignum_to_felem BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_bignum_to_felem
%xdefine _objectivepgp_ec_GFp_mont_dbl BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_dbl
%xdefine _objectivepgp_ec_GFp_mont_felem_mul BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_mul
%xdefine _objectivepgp_ec_GFp_mont_felem_sqr BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_sqr
%xdefine _objectivepgp_ec_GFp_mont_felem_to_bignum BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_felem_to_bignum
%xdefine _objectivepgp_ec_GFp_mont_group_finish BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_finish
%xdefine _objectivepgp_ec_GFp_mont_group_init BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_init
%xdefine _objectivepgp_ec_GFp_mont_group_set_curve BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_group_set_curve
%xdefine _objectivepgp_ec_GFp_mont_mul BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul
%xdefine _objectivepgp_ec_GFp_mont_mul_base BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul_base
%xdefine _objectivepgp_ec_GFp_mont_mul_public BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_mont_mul_public
%xdefine _objectivepgp_ec_GFp_nistp_recode_scalar_bits BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_nistp_recode_scalar_bits
%xdefine _objectivepgp_ec_GFp_simple_cmp BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_cmp
%xdefine _objectivepgp_ec_GFp_simple_cmp_x_coordinate BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_cmp_x_coordinate
%xdefine _objectivepgp_ec_GFp_simple_group_finish BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_finish
%xdefine _objectivepgp_ec_GFp_simple_group_get_curve BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_get_curve
%xdefine _objectivepgp_ec_GFp_simple_group_init BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_init
%xdefine _objectivepgp_ec_GFp_simple_group_set_curve BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_group_set_curve
%xdefine _objectivepgp_ec_GFp_simple_invert BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_invert
%xdefine _objectivepgp_ec_GFp_simple_is_at_infinity BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_is_at_infinity
%xdefine _objectivepgp_ec_GFp_simple_is_on_curve BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_is_on_curve
%xdefine _objectivepgp_ec_GFp_simple_mont_inv_mod_ord_vartime BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_mont_inv_mod_ord_vartime
%xdefine _objectivepgp_ec_GFp_simple_point_copy BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_copy
%xdefine _objectivepgp_ec_GFp_simple_point_init BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_init
%xdefine _objectivepgp_ec_GFp_simple_point_set_affine_coordinates BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_set_affine_coordinates
%xdefine _objectivepgp_ec_GFp_simple_point_set_to_infinity BORINGSSL_PREFIX %+ __objectivepgp_ec_GFp_simple_point_set_to_infinity
%xdefine _objectivepgp_ec_bignum_to_felem BORINGSSL_PREFIX %+ __objectivepgp_ec_bignum_to_felem
%xdefine _objectivepgp_ec_bignum_to_scalar BORINGSSL_PREFIX %+ __objectivepgp_ec_bignum_to_scalar
%xdefine _objectivepgp_ec_cmp_x_coordinate BORINGSSL_PREFIX %+ __objectivepgp_ec_cmp_x_coordinate
%xdefine _objectivepgp_ec_compute_wNAF BORINGSSL_PREFIX %+ __objectivepgp_ec_compute_wNAF
%xdefine _objectivepgp_ec_felem_add BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_add
%xdefine _objectivepgp_ec_felem_equal BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_equal
%xdefine _objectivepgp_ec_felem_neg BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_neg
%xdefine _objectivepgp_ec_felem_non_zero_mask BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_non_zero_mask
%xdefine _objectivepgp_ec_felem_select BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_select
%xdefine _objectivepgp_ec_felem_sub BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_sub
%xdefine _objectivepgp_ec_felem_to_bignum BORINGSSL_PREFIX %+ __objectivepgp_ec_felem_to_bignum
%xdefine _objectivepgp_ec_get_x_coordinate_as_scalar BORINGSSL_PREFIX %+ __objectivepgp_ec_get_x_coordinate_as_scalar
%xdefine _objectivepgp_ec_group_new BORINGSSL_PREFIX %+ __objectivepgp_ec_group_new
%xdefine _objectivepgp_ec_point_get_affine_coordinate_bytes BORINGSSL_PREFIX %+ __objectivepgp_ec_point_get_affine_coordinate_bytes
%xdefine _objectivepgp_ec_point_mul_scalar BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar
%xdefine _objectivepgp_ec_point_mul_scalar_base BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar_base
%xdefine _objectivepgp_ec_point_mul_scalar_public BORINGSSL_PREFIX %+ __objectivepgp_ec_point_mul_scalar_public
%xdefine _objectivepgp_ec_random_nonzero_scalar BORINGSSL_PREFIX %+ __objectivepgp_ec_random_nonzero_scalar
%xdefine _objectivepgp_ec_scalar_add BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_add
%xdefine _objectivepgp_ec_scalar_equal_vartime BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_equal_vartime
%xdefine _objectivepgp_ec_scalar_from_montgomery BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_from_montgomery
%xdefine _objectivepgp_ec_scalar_inv_montgomery BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_inv_montgomery
%xdefine _objectivepgp_ec_scalar_inv_montgomery_vartime BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_inv_montgomery_vartime
%xdefine _objectivepgp_ec_scalar_is_zero BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_is_zero
%xdefine _objectivepgp_ec_scalar_mul_montgomery BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_mul_montgomery
%xdefine _objectivepgp_ec_scalar_to_montgomery BORINGSSL_PREFIX %+ __objectivepgp_ec_scalar_to_montgomery
%xdefine _objectivepgp_ec_simple_scalar_inv_montgomery BORINGSSL_PREFIX %+ __objectivepgp_ec_simple_scalar_inv_montgomery
%xdefine _objectivepgp_gcm_init_4bit BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_4bit
%xdefine _objectivepgp_gcm_init_ssse3 BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_ssse3
%xdefine _objectivepgp_kBoringSSLRSASqrtTwo BORINGSSL_PREFIX %+ __objectivepgp_kBoringSSLRSASqrtTwo
%xdefine _objectivepgp_kBoringSSLRSASqrtTwoLen BORINGSSL_PREFIX %+ __objectivepgp_kBoringSSLRSASqrtTwoLen
%xdefine _objectivepgp_md4_block_data_order BORINGSSL_PREFIX %+ __objectivepgp_md4_block_data_order
%xdefine _objectivepgp_rsa_default_decrypt BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_decrypt
%xdefine _objectivepgp_rsa_default_private_transform BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_private_transform
%xdefine _objectivepgp_rsa_default_sign_raw BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_sign_raw
%xdefine _objectivepgp_rsa_default_size BORINGSSL_PREFIX %+ __objectivepgp_rsa_default_size
%xdefine _objectivepgp_FIPS_mode BORINGSSL_PREFIX %+ __objectivepgp_FIPS_mode
%xdefine _objectivepgp_FIPS_mode_set BORINGSSL_PREFIX %+ __objectivepgp_FIPS_mode_set
%xdefine _objectivepgp_aesni_gcm_decrypt BORINGSSL_PREFIX %+ __objectivepgp_aesni_gcm_decrypt
%xdefine _objectivepgp_aesni_gcm_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aesni_gcm_encrypt
%xdefine _objectivepgp_aes_hw_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_cbc_encrypt
%xdefine _objectivepgp_aes_hw_ctr32_encrypt_blocks BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_ctr32_encrypt_blocks
%xdefine _objectivepgp_aes_hw_decrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_decrypt
%xdefine _objectivepgp_aes_hw_ecb_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_ecb_encrypt
%xdefine _objectivepgp_aes_hw_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_encrypt
%xdefine _objectivepgp_aes_hw_set_decrypt_key BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_set_decrypt_key
%xdefine _objectivepgp_aes_hw_set_encrypt_key BORINGSSL_PREFIX %+ __objectivepgp_aes_hw_set_encrypt_key
%xdefine _objectivepgp_aes_nohw_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_cbc_encrypt
%xdefine _objectivepgp_aes_nohw_decrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_decrypt
%xdefine _objectivepgp_aes_nohw_encrypt BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_encrypt
%xdefine _objectivepgp_aes_nohw_set_decrypt_key BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_set_decrypt_key
%xdefine _objectivepgp_aes_nohw_set_encrypt_key BORINGSSL_PREFIX %+ __objectivepgp_aes_nohw_set_encrypt_key
%xdefine _objectivepgp_gcm_ghash_ssse3 BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_ssse3
%xdefine _objectivepgp_gcm_gmult_ssse3 BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_ssse3
%xdefine _objectivepgp_gcm_ghash_4bit BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_4bit
%xdefine _objectivepgp_gcm_ghash_avx BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_avx
%xdefine _objectivepgp_gcm_ghash_clmul BORINGSSL_PREFIX %+ __objectivepgp_gcm_ghash_clmul
%xdefine _objectivepgp_gcm_gmult_4bit BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_4bit
%xdefine _objectivepgp_gcm_gmult_avx BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_avx
%xdefine _objectivepgp_gcm_gmult_clmul BORINGSSL_PREFIX %+ __objectivepgp_gcm_gmult_clmul
%xdefine _objectivepgp_gcm_init_avx BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_avx
%xdefine _objectivepgp_gcm_init_clmul BORINGSSL_PREFIX %+ __objectivepgp_gcm_init_clmul
%xdefine _objectivepgp_md5_block_asm_data_order BORINGSSL_PREFIX %+ __objectivepgp_md5_block_asm_data_order
%xdefine _objectivepgp_ecp_nistz256_avx2_select_w7 BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_avx2_select_w7
%xdefine _objectivepgp_ecp_nistz256_mul_mont BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_mul_mont
%xdefine _objectivepgp_ecp_nistz256_neg BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_neg
%xdefine _objectivepgp_ecp_nistz256_ord_mul_mont BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_ord_mul_mont
%xdefine _objectivepgp_ecp_nistz256_ord_sqr_mont BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_ord_sqr_mont
%xdefine _objectivepgp_ecp_nistz256_point_add BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_add
%xdefine _objectivepgp_ecp_nistz256_point_add_affine BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_add_affine
%xdefine _objectivepgp_ecp_nistz256_point_double BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_point_double
%xdefine _objectivepgp_ecp_nistz256_select_w5 BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_select_w5
%xdefine _objectivepgp_ecp_nistz256_select_w7 BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_select_w7
%xdefine _objectivepgp_ecp_nistz256_sqr_mont BORINGSSL_PREFIX %+ __objectivepgp_ecp_nistz256_sqr_mont
%xdefine _objectivepgp_beeu_mod_inverse_vartime BORINGSSL_PREFIX %+ __objectivepgp_beeu_mod_inverse_vartime
%xdefine _objectivepgp_CRYPTO_rdrand BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_rdrand
%xdefine _objectivepgp_CRYPTO_rdrand_multiple8_buf BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_rdrand_multiple8_buf
%xdefine _objectivepgp_rsaz_1024_gather5_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_gather5_avx2
%xdefine _objectivepgp_rsaz_1024_mul_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_mul_avx2
%xdefine _objectivepgp_rsaz_1024_norm2red_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_norm2red_avx2
%xdefine _objectivepgp_rsaz_1024_red2norm_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_red2norm_avx2
%xdefine _objectivepgp_rsaz_1024_scatter5_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_scatter5_avx2
%xdefine _objectivepgp_rsaz_1024_sqr_avx2 BORINGSSL_PREFIX %+ __objectivepgp_rsaz_1024_sqr_avx2
%xdefine _objectivepgp_sha1_block_data_order BORINGSSL_PREFIX %+ __objectivepgp_sha1_block_data_order
%xdefine _objectivepgp_sha256_block_data_order BORINGSSL_PREFIX %+ __objectivepgp_sha256_block_data_order
%xdefine _objectivepgp_sha512_block_data_order BORINGSSL_PREFIX %+ __objectivepgp_sha512_block_data_order
%xdefine _objectivepgp_vpaes_cbc_encrypt BORINGSSL_PREFIX %+ __objectivepgp_vpaes_cbc_encrypt
%xdefine _objectivepgp_vpaes_ctr32_encrypt_blocks BORINGSSL_PREFIX %+ __objectivepgp_vpaes_ctr32_encrypt_blocks
%xdefine _objectivepgp_vpaes_decrypt BORINGSSL_PREFIX %+ __objectivepgp_vpaes_decrypt
%xdefine _objectivepgp_vpaes_encrypt BORINGSSL_PREFIX %+ __objectivepgp_vpaes_encrypt
%xdefine _objectivepgp_vpaes_set_decrypt_key BORINGSSL_PREFIX %+ __objectivepgp_vpaes_set_decrypt_key
%xdefine _objectivepgp_vpaes_set_encrypt_key BORINGSSL_PREFIX %+ __objectivepgp_vpaes_set_encrypt_key
%xdefine _objectivepgp_bn_from_montgomery BORINGSSL_PREFIX %+ __objectivepgp_bn_from_montgomery
%xdefine _objectivepgp_bn_gather5 BORINGSSL_PREFIX %+ __objectivepgp_bn_gather5
%xdefine _objectivepgp_bn_mul_mont_gather5 BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_mont_gather5
%xdefine _objectivepgp_bn_power5 BORINGSSL_PREFIX %+ __objectivepgp_bn_power5
%xdefine _objectivepgp_bn_scatter5 BORINGSSL_PREFIX %+ __objectivepgp_bn_scatter5
%xdefine _objectivepgp_bn_sqr8x_internal BORINGSSL_PREFIX %+ __objectivepgp_bn_sqr8x_internal
%xdefine _objectivepgp_bn_sqrx8x_internal BORINGSSL_PREFIX %+ __objectivepgp_bn_sqrx8x_internal
%xdefine _objectivepgp_bn_mul_mont BORINGSSL_PREFIX %+ __objectivepgp_bn_mul_mont
%xdefine _objectivepgp_ASN1_BIT_STRING_check BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_check
%xdefine _objectivepgp_ASN1_BIT_STRING_get_bit BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_get_bit
%xdefine _objectivepgp_ASN1_BIT_STRING_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_set
%xdefine _objectivepgp_ASN1_BIT_STRING_set_bit BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_set_bit
%xdefine _objectivepgp_c2i_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_BIT_STRING
%xdefine _objectivepgp_i2c_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2c_ASN1_BIT_STRING
%xdefine _objectivepgp_d2i_ASN1_BOOLEAN BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BOOLEAN
%xdefine _objectivepgp_i2d_ASN1_BOOLEAN BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BOOLEAN
%xdefine _objectivepgp_ASN1_item_d2i_bio BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i_bio
%xdefine _objectivepgp_ASN1_item_d2i_fp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i_fp
%xdefine _objectivepgp_ASN1_item_dup BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_dup
%xdefine _objectivepgp_ASN1_ENUMERATED_get BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_get
%xdefine _objectivepgp_ASN1_ENUMERATED_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_set
%xdefine _objectivepgp_ASN1_ENUMERATED_to_BN BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_to_BN
%xdefine _objectivepgp_BN_to_ASN1_ENUMERATED BORINGSSL_PREFIX %+ __objectivepgp_BN_to_ASN1_ENUMERATED
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_adj BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_adj
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_check BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_check
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_set
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_set_string BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_set_string
%xdefine _objectivepgp_asn1_generalizedtime_to_tm BORINGSSL_PREFIX %+ __objectivepgp_asn1_generalizedtime_to_tm
%xdefine _objectivepgp_ASN1_item_i2d_bio BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d_bio
%xdefine _objectivepgp_ASN1_item_i2d_fp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d_fp
%xdefine _objectivepgp_ASN1_INTEGER_cmp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_cmp
%xdefine _objectivepgp_ASN1_INTEGER_dup BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_dup
%xdefine _objectivepgp_ASN1_INTEGER_get BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_get
%xdefine _objectivepgp_ASN1_INTEGER_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_set
%xdefine _objectivepgp_ASN1_INTEGER_set_uint64 BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_set_uint64
%xdefine _objectivepgp_ASN1_INTEGER_to_BN BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_to_BN
%xdefine _objectivepgp_BN_to_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_BN_to_ASN1_INTEGER
%xdefine _objectivepgp_c2i_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_INTEGER
%xdefine _objectivepgp_i2c_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_i2c_ASN1_INTEGER
%xdefine _objectivepgp_ASN1_mbstring_copy BORINGSSL_PREFIX %+ __objectivepgp_ASN1_mbstring_copy
%xdefine _objectivepgp_ASN1_mbstring_ncopy BORINGSSL_PREFIX %+ __objectivepgp_ASN1_mbstring_ncopy
%xdefine _objectivepgp_ASN1_OBJECT_create BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_create
%xdefine _objectivepgp_ASN1_OBJECT_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_free
%xdefine _objectivepgp_ASN1_OBJECT_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_new
%xdefine _objectivepgp_c2i_ASN1_OBJECT BORINGSSL_PREFIX %+ __objectivepgp_c2i_ASN1_OBJECT
%xdefine _objectivepgp_d2i_ASN1_OBJECT BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_OBJECT
%xdefine _objectivepgp_i2a_ASN1_OBJECT BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_OBJECT
%xdefine _objectivepgp_i2d_ASN1_OBJECT BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_OBJECT
%xdefine _objectivepgp_i2t_ASN1_OBJECT BORINGSSL_PREFIX %+ __objectivepgp_i2t_ASN1_OBJECT
%xdefine _objectivepgp_ASN1_OCTET_STRING_cmp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_cmp
%xdefine _objectivepgp_ASN1_OCTET_STRING_dup BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_dup
%xdefine _objectivepgp_ASN1_OCTET_STRING_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_set
%xdefine _objectivepgp_ASN1_PRINTABLE_type BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_type
%xdefine _objectivepgp_ASN1_STRING_TABLE_add BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_add
%xdefine _objectivepgp_ASN1_STRING_TABLE_cleanup BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_cleanup
%xdefine _objectivepgp_ASN1_STRING_TABLE_get BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_TABLE_get
%xdefine _objectivepgp_ASN1_STRING_get_default_mask BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_get_default_mask
%xdefine _objectivepgp_ASN1_STRING_set_by_NID BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_by_NID
%xdefine _objectivepgp_ASN1_STRING_set_default_mask BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_default_mask
%xdefine _objectivepgp_ASN1_STRING_set_default_mask_asc BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set_default_mask_asc
%xdefine _objectivepgp_ASN1_TIME_adj BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_adj
%xdefine _objectivepgp_ASN1_TIME_check BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_check
%xdefine _objectivepgp_ASN1_TIME_diff BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_diff
%xdefine _objectivepgp_ASN1_TIME_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_free
%xdefine _objectivepgp_ASN1_TIME_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_it
%xdefine _objectivepgp_ASN1_TIME_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_new
%xdefine _objectivepgp_ASN1_TIME_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_set
%xdefine _objectivepgp_ASN1_TIME_set_string BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_set_string
%xdefine _objectivepgp_ASN1_TIME_to_generalizedtime BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_to_generalizedtime
%xdefine _objectivepgp_d2i_ASN1_TIME BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_TIME
%xdefine _objectivepgp_i2d_ASN1_TIME BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_TIME
%xdefine _objectivepgp_ASN1_TYPE_cmp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_cmp
%xdefine _objectivepgp_ASN1_TYPE_get BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_get
%xdefine _objectivepgp_ASN1_TYPE_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_set
%xdefine _objectivepgp_ASN1_TYPE_set1 BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_set1
%xdefine _objectivepgp_ASN1_UTCTIME_adj BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_adj
%xdefine _objectivepgp_ASN1_UTCTIME_check BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_check
%xdefine _objectivepgp_ASN1_UTCTIME_cmp_time_t BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_cmp_time_t
%xdefine _objectivepgp_ASN1_UTCTIME_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_set
%xdefine _objectivepgp_ASN1_UTCTIME_set_string BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_set_string
%xdefine _objectivepgp_asn1_utctime_to_tm BORINGSSL_PREFIX %+ __objectivepgp_asn1_utctime_to_tm
%xdefine _objectivepgp_UTF8_getc BORINGSSL_PREFIX %+ __objectivepgp_UTF8_getc
%xdefine _objectivepgp_UTF8_putc BORINGSSL_PREFIX %+ __objectivepgp_UTF8_putc
%xdefine _objectivepgp_ASN1_STRING_cmp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_cmp
%xdefine _objectivepgp_ASN1_STRING_copy BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_copy
%xdefine _objectivepgp_ASN1_STRING_data BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_data
%xdefine _objectivepgp_ASN1_STRING_dup BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_dup
%xdefine _objectivepgp_ASN1_STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_free
%xdefine _objectivepgp_ASN1_STRING_get0_data BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_get0_data
%xdefine _objectivepgp_ASN1_STRING_length BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_length
%xdefine _objectivepgp_ASN1_STRING_length_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_length_set
%xdefine _objectivepgp_ASN1_STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_new
%xdefine _objectivepgp_ASN1_STRING_set BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set
%xdefine _objectivepgp_ASN1_STRING_set0 BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_set0
%xdefine _objectivepgp_ASN1_STRING_type BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_type
%xdefine _objectivepgp_ASN1_STRING_type_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_type_new
%xdefine _objectivepgp_ASN1_get_object BORINGSSL_PREFIX %+ __objectivepgp_ASN1_get_object
%xdefine _objectivepgp_ASN1_object_size BORINGSSL_PREFIX %+ __objectivepgp_ASN1_object_size
%xdefine _objectivepgp_ASN1_put_eoc BORINGSSL_PREFIX %+ __objectivepgp_ASN1_put_eoc
%xdefine _objectivepgp_ASN1_put_object BORINGSSL_PREFIX %+ __objectivepgp_ASN1_put_object
%xdefine _objectivepgp_ASN1_tag2str BORINGSSL_PREFIX %+ __objectivepgp_ASN1_tag2str
%xdefine _objectivepgp_ASN1_item_pack BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_pack
%xdefine _objectivepgp_ASN1_item_unpack BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_unpack
%xdefine _objectivepgp_i2a_ASN1_ENUMERATED BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_ENUMERATED
%xdefine _objectivepgp_i2a_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_INTEGER
%xdefine _objectivepgp_i2a_ASN1_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2a_ASN1_STRING
%xdefine _objectivepgp_ASN1_item_d2i BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_d2i
%xdefine _objectivepgp_ASN1_item_ex_d2i BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_d2i
%xdefine _objectivepgp_ASN1_tag2bit BORINGSSL_PREFIX %+ __objectivepgp_ASN1_tag2bit
%xdefine _objectivepgp_asn1_ex_c2i BORINGSSL_PREFIX %+ __objectivepgp_asn1_ex_c2i
%xdefine _objectivepgp_ASN1_item_ex_i2d BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_i2d
%xdefine _objectivepgp_ASN1_item_i2d BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_i2d
%xdefine _objectivepgp_ASN1_item_ndef_i2d BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ndef_i2d
%xdefine _objectivepgp_asn1_ex_i2c BORINGSSL_PREFIX %+ __objectivepgp_asn1_ex_i2c
%xdefine _objectivepgp_ASN1_item_ex_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_free
%xdefine _objectivepgp_ASN1_item_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_free
%xdefine _objectivepgp_ASN1_primitive_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_primitive_free
%xdefine _objectivepgp_ASN1_template_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_template_free
%xdefine _objectivepgp_asn1_item_combine_free BORINGSSL_PREFIX %+ __objectivepgp_asn1_item_combine_free
%xdefine _objectivepgp_ASN1_item_ex_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_ex_new
%xdefine _objectivepgp_ASN1_item_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_new
%xdefine _objectivepgp_ASN1_primitive_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_primitive_new
%xdefine _objectivepgp_ASN1_template_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_template_new
%xdefine _objectivepgp_ASN1_ANY_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ANY_it
%xdefine _objectivepgp_ASN1_BIT_STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_free
%xdefine _objectivepgp_ASN1_BIT_STRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_it
%xdefine _objectivepgp_ASN1_BIT_STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BIT_STRING_new
%xdefine _objectivepgp_ASN1_BMPSTRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_free
%xdefine _objectivepgp_ASN1_BMPSTRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_it
%xdefine _objectivepgp_ASN1_BMPSTRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BMPSTRING_new
%xdefine _objectivepgp_ASN1_BOOLEAN_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_BOOLEAN_it
%xdefine _objectivepgp_ASN1_ENUMERATED_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_free
%xdefine _objectivepgp_ASN1_ENUMERATED_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_it
%xdefine _objectivepgp_ASN1_ENUMERATED_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_ENUMERATED_new
%xdefine _objectivepgp_ASN1_FBOOLEAN_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_FBOOLEAN_it
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_free
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_it
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_new
%xdefine _objectivepgp_ASN1_GENERALSTRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_free
%xdefine _objectivepgp_ASN1_GENERALSTRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_it
%xdefine _objectivepgp_ASN1_GENERALSTRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALSTRING_new
%xdefine _objectivepgp_ASN1_IA5STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_free
%xdefine _objectivepgp_ASN1_IA5STRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_it
%xdefine _objectivepgp_ASN1_IA5STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_IA5STRING_new
%xdefine _objectivepgp_ASN1_INTEGER_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_free
%xdefine _objectivepgp_ASN1_INTEGER_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_it
%xdefine _objectivepgp_ASN1_INTEGER_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_INTEGER_new
%xdefine _objectivepgp_ASN1_NULL_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_free
%xdefine _objectivepgp_ASN1_NULL_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_it
%xdefine _objectivepgp_ASN1_NULL_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_NULL_new
%xdefine _objectivepgp_ASN1_OBJECT_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OBJECT_it
%xdefine _objectivepgp_ASN1_OCTET_STRING_NDEF_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_NDEF_it
%xdefine _objectivepgp_ASN1_OCTET_STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_free
%xdefine _objectivepgp_ASN1_OCTET_STRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_it
%xdefine _objectivepgp_ASN1_OCTET_STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_OCTET_STRING_new
%xdefine _objectivepgp_ASN1_PRINTABLESTRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_free
%xdefine _objectivepgp_ASN1_PRINTABLESTRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_it
%xdefine _objectivepgp_ASN1_PRINTABLESTRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLESTRING_new
%xdefine _objectivepgp_ASN1_PRINTABLE_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_free
%xdefine _objectivepgp_ASN1_PRINTABLE_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_it
%xdefine _objectivepgp_ASN1_PRINTABLE_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_PRINTABLE_new
%xdefine _objectivepgp_ASN1_SEQUENCE_ANY_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SEQUENCE_ANY_it
%xdefine _objectivepgp_ASN1_SEQUENCE_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SEQUENCE_it
%xdefine _objectivepgp_ASN1_SET_ANY_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_SET_ANY_it
%xdefine _objectivepgp_ASN1_T61STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_free
%xdefine _objectivepgp_ASN1_T61STRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_it
%xdefine _objectivepgp_ASN1_T61STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_T61STRING_new
%xdefine _objectivepgp_ASN1_TBOOLEAN_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TBOOLEAN_it
%xdefine _objectivepgp_ASN1_TYPE_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_free
%xdefine _objectivepgp_ASN1_TYPE_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TYPE_new
%xdefine _objectivepgp_ASN1_UNIVERSALSTRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_free
%xdefine _objectivepgp_ASN1_UNIVERSALSTRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_it
%xdefine _objectivepgp_ASN1_UNIVERSALSTRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UNIVERSALSTRING_new
%xdefine _objectivepgp_ASN1_UTCTIME_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_free
%xdefine _objectivepgp_ASN1_UTCTIME_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_it
%xdefine _objectivepgp_ASN1_UTCTIME_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_new
%xdefine _objectivepgp_ASN1_UTF8STRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_free
%xdefine _objectivepgp_ASN1_UTF8STRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_it
%xdefine _objectivepgp_ASN1_UTF8STRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTF8STRING_new
%xdefine _objectivepgp_ASN1_VISIBLESTRING_free BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_free
%xdefine _objectivepgp_ASN1_VISIBLESTRING_it BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_it
%xdefine _objectivepgp_ASN1_VISIBLESTRING_new BORINGSSL_PREFIX %+ __objectivepgp_ASN1_VISIBLESTRING_new
%xdefine _objectivepgp_DIRECTORYSTRING_free BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_free
%xdefine _objectivepgp_DIRECTORYSTRING_it BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_it
%xdefine _objectivepgp_DIRECTORYSTRING_new BORINGSSL_PREFIX %+ __objectivepgp_DIRECTORYSTRING_new
%xdefine _objectivepgp_DISPLAYTEXT_free BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_free
%xdefine _objectivepgp_DISPLAYTEXT_it BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_it
%xdefine _objectivepgp_DISPLAYTEXT_new BORINGSSL_PREFIX %+ __objectivepgp_DISPLAYTEXT_new
%xdefine _objectivepgp_d2i_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BIT_STRING
%xdefine _objectivepgp_d2i_ASN1_BMPSTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_BMPSTRING
%xdefine _objectivepgp_d2i_ASN1_ENUMERATED BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_ENUMERATED
%xdefine _objectivepgp_d2i_ASN1_GENERALIZEDTIME BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_GENERALIZEDTIME
%xdefine _objectivepgp_d2i_ASN1_GENERALSTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_GENERALSTRING
%xdefine _objectivepgp_d2i_ASN1_IA5STRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_IA5STRING
%xdefine _objectivepgp_d2i_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_INTEGER
%xdefine _objectivepgp_d2i_ASN1_NULL BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_NULL
%xdefine _objectivepgp_d2i_ASN1_OCTET_STRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_OCTET_STRING
%xdefine _objectivepgp_d2i_ASN1_PRINTABLE BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_PRINTABLE
%xdefine _objectivepgp_d2i_ASN1_PRINTABLESTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_PRINTABLESTRING
%xdefine _objectivepgp_d2i_ASN1_SEQUENCE_ANY BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_SEQUENCE_ANY
%xdefine _objectivepgp_d2i_ASN1_SET_ANY BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_SET_ANY
%xdefine _objectivepgp_d2i_ASN1_T61STRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_T61STRING
%xdefine _objectivepgp_d2i_ASN1_TYPE BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_TYPE
%xdefine _objectivepgp_d2i_ASN1_UNIVERSALSTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UNIVERSALSTRING
%xdefine _objectivepgp_d2i_ASN1_UTCTIME BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UTCTIME
%xdefine _objectivepgp_d2i_ASN1_UTF8STRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_UTF8STRING
%xdefine _objectivepgp_d2i_ASN1_VISIBLESTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_ASN1_VISIBLESTRING
%xdefine _objectivepgp_d2i_DIRECTORYSTRING BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIRECTORYSTRING
%xdefine _objectivepgp_d2i_DISPLAYTEXT BORINGSSL_PREFIX %+ __objectivepgp_d2i_DISPLAYTEXT
%xdefine _objectivepgp_i2d_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BIT_STRING
%xdefine _objectivepgp_i2d_ASN1_BMPSTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_BMPSTRING
%xdefine _objectivepgp_i2d_ASN1_ENUMERATED BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_ENUMERATED
%xdefine _objectivepgp_i2d_ASN1_GENERALIZEDTIME BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_GENERALIZEDTIME
%xdefine _objectivepgp_i2d_ASN1_GENERALSTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_GENERALSTRING
%xdefine _objectivepgp_i2d_ASN1_IA5STRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_IA5STRING
%xdefine _objectivepgp_i2d_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_INTEGER
%xdefine _objectivepgp_i2d_ASN1_NULL BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_NULL
%xdefine _objectivepgp_i2d_ASN1_OCTET_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_OCTET_STRING
%xdefine _objectivepgp_i2d_ASN1_PRINTABLE BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_PRINTABLE
%xdefine _objectivepgp_i2d_ASN1_PRINTABLESTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_PRINTABLESTRING
%xdefine _objectivepgp_i2d_ASN1_SEQUENCE_ANY BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_SEQUENCE_ANY
%xdefine _objectivepgp_i2d_ASN1_SET_ANY BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_SET_ANY
%xdefine _objectivepgp_i2d_ASN1_T61STRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_T61STRING
%xdefine _objectivepgp_i2d_ASN1_TYPE BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_TYPE
%xdefine _objectivepgp_i2d_ASN1_UNIVERSALSTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UNIVERSALSTRING
%xdefine _objectivepgp_i2d_ASN1_UTCTIME BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UTCTIME
%xdefine _objectivepgp_i2d_ASN1_UTF8STRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_UTF8STRING
%xdefine _objectivepgp_i2d_ASN1_VISIBLESTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_ASN1_VISIBLESTRING
%xdefine _objectivepgp_i2d_DIRECTORYSTRING BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIRECTORYSTRING
%xdefine _objectivepgp_i2d_DISPLAYTEXT BORINGSSL_PREFIX %+ __objectivepgp_i2d_DISPLAYTEXT
%xdefine _objectivepgp_asn1_do_adb BORINGSSL_PREFIX %+ __objectivepgp_asn1_do_adb
%xdefine _objectivepgp_asn1_enc_free BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_free
%xdefine _objectivepgp_asn1_enc_init BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_init
%xdefine _objectivepgp_asn1_enc_restore BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_restore
%xdefine _objectivepgp_asn1_enc_save BORINGSSL_PREFIX %+ __objectivepgp_asn1_enc_save
%xdefine _objectivepgp_asn1_get_choice_selector BORINGSSL_PREFIX %+ __objectivepgp_asn1_get_choice_selector
%xdefine _objectivepgp_asn1_get_field_ptr BORINGSSL_PREFIX %+ __objectivepgp_asn1_get_field_ptr
%xdefine _objectivepgp_asn1_refcount_dec_and_test_zero BORINGSSL_PREFIX %+ __objectivepgp_asn1_refcount_dec_and_test_zero
%xdefine _objectivepgp_asn1_refcount_set_one BORINGSSL_PREFIX %+ __objectivepgp_asn1_refcount_set_one
%xdefine _objectivepgp_asn1_set_choice_selector BORINGSSL_PREFIX %+ __objectivepgp_asn1_set_choice_selector
%xdefine _objectivepgp_OPENSSL_gmtime BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime
%xdefine _objectivepgp_OPENSSL_gmtime_adj BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime_adj
%xdefine _objectivepgp_OPENSSL_gmtime_diff BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_gmtime_diff
%xdefine _objectivepgp_EVP_DecodeBase64 BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeBase64
%xdefine _objectivepgp_EVP_DecodeBlock BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeBlock
%xdefine _objectivepgp_EVP_DecodeFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeFinal
%xdefine _objectivepgp_EVP_DecodeInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeInit
%xdefine _objectivepgp_EVP_DecodeUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodeUpdate
%xdefine _objectivepgp_EVP_DecodedLength BORINGSSL_PREFIX %+ __objectivepgp_EVP_DecodedLength
%xdefine _objectivepgp_EVP_EncodeBlock BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeBlock
%xdefine _objectivepgp_EVP_EncodeFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeFinal
%xdefine _objectivepgp_EVP_EncodeInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeInit
%xdefine _objectivepgp_EVP_EncodeUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodeUpdate
%xdefine _objectivepgp_EVP_EncodedLength BORINGSSL_PREFIX %+ __objectivepgp_EVP_EncodedLength
%xdefine _objectivepgp_BIO_callback_ctrl BORINGSSL_PREFIX %+ __objectivepgp_BIO_callback_ctrl
%xdefine _objectivepgp_BIO_clear_flags BORINGSSL_PREFIX %+ __objectivepgp_BIO_clear_flags
%xdefine _objectivepgp_BIO_clear_retry_flags BORINGSSL_PREFIX %+ __objectivepgp_BIO_clear_retry_flags
%xdefine _objectivepgp_BIO_copy_next_retry BORINGSSL_PREFIX %+ __objectivepgp_BIO_copy_next_retry
%xdefine _objectivepgp_BIO_ctrl BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl
%xdefine _objectivepgp_BIO_ctrl_pending BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_pending
%xdefine _objectivepgp_BIO_eof BORINGSSL_PREFIX %+ __objectivepgp_BIO_eof
%xdefine _objectivepgp_BIO_find_type BORINGSSL_PREFIX %+ __objectivepgp_BIO_find_type
%xdefine _objectivepgp_BIO_flush BORINGSSL_PREFIX %+ __objectivepgp_BIO_flush
%xdefine _objectivepgp_BIO_free BORINGSSL_PREFIX %+ __objectivepgp_BIO_free
%xdefine _objectivepgp_BIO_free_all BORINGSSL_PREFIX %+ __objectivepgp_BIO_free_all
%xdefine _objectivepgp_BIO_get_data BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_data
%xdefine _objectivepgp_BIO_get_init BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_init
%xdefine _objectivepgp_BIO_get_new_index BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_new_index
%xdefine _objectivepgp_BIO_get_retry_flags BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_retry_flags
%xdefine _objectivepgp_BIO_get_retry_reason BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_retry_reason
%xdefine _objectivepgp_BIO_get_shutdown BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_shutdown
%xdefine _objectivepgp_BIO_gets BORINGSSL_PREFIX %+ __objectivepgp_BIO_gets
%xdefine _objectivepgp_BIO_indent BORINGSSL_PREFIX %+ __objectivepgp_BIO_indent
%xdefine _objectivepgp_BIO_int_ctrl BORINGSSL_PREFIX %+ __objectivepgp_BIO_int_ctrl
%xdefine _objectivepgp_BIO_meth_free BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_free
%xdefine _objectivepgp_BIO_meth_new BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_new
%xdefine _objectivepgp_BIO_meth_set_create BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_create
%xdefine _objectivepgp_BIO_meth_set_ctrl BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_ctrl
%xdefine _objectivepgp_BIO_meth_set_destroy BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_destroy
%xdefine _objectivepgp_BIO_meth_set_gets BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_gets
%xdefine _objectivepgp_BIO_meth_set_puts BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_puts
%xdefine _objectivepgp_BIO_meth_set_read BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_read
%xdefine _objectivepgp_BIO_meth_set_write BORINGSSL_PREFIX %+ __objectivepgp_BIO_meth_set_write
%xdefine _objectivepgp_BIO_method_type BORINGSSL_PREFIX %+ __objectivepgp_BIO_method_type
%xdefine _objectivepgp_BIO_new BORINGSSL_PREFIX %+ __objectivepgp_BIO_new
%xdefine _objectivepgp_BIO_next BORINGSSL_PREFIX %+ __objectivepgp_BIO_next
%xdefine _objectivepgp_BIO_number_read BORINGSSL_PREFIX %+ __objectivepgp_BIO_number_read
%xdefine _objectivepgp_BIO_number_written BORINGSSL_PREFIX %+ __objectivepgp_BIO_number_written
%xdefine _objectivepgp_BIO_pending BORINGSSL_PREFIX %+ __objectivepgp_BIO_pending
%xdefine _objectivepgp_BIO_pop BORINGSSL_PREFIX %+ __objectivepgp_BIO_pop
%xdefine _objectivepgp_BIO_ptr_ctrl BORINGSSL_PREFIX %+ __objectivepgp_BIO_ptr_ctrl
%xdefine _objectivepgp_BIO_push BORINGSSL_PREFIX %+ __objectivepgp_BIO_push
%xdefine _objectivepgp_BIO_puts BORINGSSL_PREFIX %+ __objectivepgp_BIO_puts
%xdefine _objectivepgp_BIO_read BORINGSSL_PREFIX %+ __objectivepgp_BIO_read
%xdefine _objectivepgp_BIO_read_asn1 BORINGSSL_PREFIX %+ __objectivepgp_BIO_read_asn1
%xdefine _objectivepgp_BIO_reset BORINGSSL_PREFIX %+ __objectivepgp_BIO_reset
%xdefine _objectivepgp_BIO_set_close BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_close
%xdefine _objectivepgp_BIO_set_data BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_data
%xdefine _objectivepgp_BIO_set_flags BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_flags
%xdefine _objectivepgp_BIO_set_init BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_init
%xdefine _objectivepgp_BIO_set_retry_read BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_read
%xdefine _objectivepgp_BIO_set_retry_special BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_special
%xdefine _objectivepgp_BIO_set_retry_write BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_retry_write
%xdefine _objectivepgp_BIO_set_shutdown BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_shutdown
%xdefine _objectivepgp_BIO_set_write_buffer_size BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_write_buffer_size
%xdefine _objectivepgp_BIO_should_io_special BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_io_special
%xdefine _objectivepgp_BIO_should_read BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_read
%xdefine _objectivepgp_BIO_should_retry BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_retry
%xdefine _objectivepgp_BIO_should_write BORINGSSL_PREFIX %+ __objectivepgp_BIO_should_write
%xdefine _objectivepgp_BIO_test_flags BORINGSSL_PREFIX %+ __objectivepgp_BIO_test_flags
%xdefine _objectivepgp_BIO_up_ref BORINGSSL_PREFIX %+ __objectivepgp_BIO_up_ref
%xdefine _objectivepgp_BIO_vfree BORINGSSL_PREFIX %+ __objectivepgp_BIO_vfree
%xdefine _objectivepgp_BIO_wpending BORINGSSL_PREFIX %+ __objectivepgp_BIO_wpending
%xdefine _objectivepgp_BIO_write BORINGSSL_PREFIX %+ __objectivepgp_BIO_write
%xdefine _objectivepgp_BIO_write_all BORINGSSL_PREFIX %+ __objectivepgp_BIO_write_all
%xdefine _objectivepgp_ERR_print_errors BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors
%xdefine _objectivepgp_BIO_get_mem_data BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_mem_data
%xdefine _objectivepgp_BIO_get_mem_ptr BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_mem_ptr
%xdefine _objectivepgp_BIO_mem_contents BORINGSSL_PREFIX %+ __objectivepgp_BIO_mem_contents
%xdefine _objectivepgp_BIO_new_mem_buf BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_mem_buf
%xdefine _objectivepgp_BIO_s_mem BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_mem
%xdefine _objectivepgp_BIO_set_mem_buf BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_mem_buf
%xdefine _objectivepgp_BIO_set_mem_eof_return BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_mem_eof_return
%xdefine _objectivepgp_BIO_do_connect BORINGSSL_PREFIX %+ __objectivepgp_BIO_do_connect
%xdefine _objectivepgp_BIO_new_connect BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_connect
%xdefine _objectivepgp_BIO_s_connect BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_connect
%xdefine _objectivepgp_BIO_set_conn_hostname BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_hostname
%xdefine _objectivepgp_BIO_set_conn_int_port BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_int_port
%xdefine _objectivepgp_BIO_set_conn_port BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_conn_port
%xdefine _objectivepgp_BIO_set_nbio BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_nbio
%xdefine _objectivepgp_BIO_get_fd BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_fd
%xdefine _objectivepgp_BIO_new_fd BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_fd
%xdefine _objectivepgp_BIO_s_fd BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_fd
%xdefine _objectivepgp_BIO_set_fd BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_fd
%xdefine _objectivepgp_bio_fd_should_retry BORINGSSL_PREFIX %+ __objectivepgp_bio_fd_should_retry
%xdefine _objectivepgp_BIO_append_filename BORINGSSL_PREFIX %+ __objectivepgp_BIO_append_filename
%xdefine _objectivepgp_BIO_get_fp BORINGSSL_PREFIX %+ __objectivepgp_BIO_get_fp
%xdefine _objectivepgp_BIO_new_file BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_file
%xdefine _objectivepgp_BIO_new_fp BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_fp
%xdefine _objectivepgp_BIO_read_filename BORINGSSL_PREFIX %+ __objectivepgp_BIO_read_filename
%xdefine _objectivepgp_BIO_rw_filename BORINGSSL_PREFIX %+ __objectivepgp_BIO_rw_filename
%xdefine _objectivepgp_BIO_s_file BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_file
%xdefine _objectivepgp_BIO_set_fp BORINGSSL_PREFIX %+ __objectivepgp_BIO_set_fp
%xdefine _objectivepgp_BIO_write_filename BORINGSSL_PREFIX %+ __objectivepgp_BIO_write_filename
%xdefine _objectivepgp_BIO_hexdump BORINGSSL_PREFIX %+ __objectivepgp_BIO_hexdump
%xdefine _objectivepgp_BIO_ctrl_get_read_request BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_get_read_request
%xdefine _objectivepgp_BIO_ctrl_get_write_guarantee BORINGSSL_PREFIX %+ __objectivepgp_BIO_ctrl_get_write_guarantee
%xdefine _objectivepgp_BIO_new_bio_pair BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_bio_pair
%xdefine _objectivepgp_BIO_shutdown_wr BORINGSSL_PREFIX %+ __objectivepgp_BIO_shutdown_wr
%xdefine _objectivepgp_BIO_printf BORINGSSL_PREFIX %+ __objectivepgp_BIO_printf
%xdefine _objectivepgp_BIO_new_socket BORINGSSL_PREFIX %+ __objectivepgp_BIO_new_socket
%xdefine _objectivepgp_BIO_s_socket BORINGSSL_PREFIX %+ __objectivepgp_BIO_s_socket
%xdefine _objectivepgp_bio_clear_socket_error BORINGSSL_PREFIX %+ __objectivepgp_bio_clear_socket_error
%xdefine _objectivepgp_bio_ip_and_port_to_socket_and_addr BORINGSSL_PREFIX %+ __objectivepgp_bio_ip_and_port_to_socket_and_addr
%xdefine _objectivepgp_bio_sock_error BORINGSSL_PREFIX %+ __objectivepgp_bio_sock_error
%xdefine _objectivepgp_bio_socket_nbio BORINGSSL_PREFIX %+ __objectivepgp_bio_socket_nbio
%xdefine _objectivepgp_BN_marshal_asn1 BORINGSSL_PREFIX %+ __objectivepgp_BN_marshal_asn1
%xdefine _objectivepgp_BN_parse_asn1_unsigned BORINGSSL_PREFIX %+ __objectivepgp_BN_parse_asn1_unsigned
%xdefine _objectivepgp_BN_asc2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_asc2bn
%xdefine _objectivepgp_BN_bn2binpad BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2binpad
%xdefine _objectivepgp_BN_bn2cbb_padded BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2cbb_padded
%xdefine _objectivepgp_BN_bn2dec BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2dec
%xdefine _objectivepgp_BN_bn2hex BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2hex
%xdefine _objectivepgp_BN_bn2mpi BORINGSSL_PREFIX %+ __objectivepgp_BN_bn2mpi
%xdefine _objectivepgp_BN_dec2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_dec2bn
%xdefine _objectivepgp_BN_hex2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_hex2bn
%xdefine _objectivepgp_BN_mpi2bn BORINGSSL_PREFIX %+ __objectivepgp_BN_mpi2bn
%xdefine _objectivepgp_BN_print BORINGSSL_PREFIX %+ __objectivepgp_BN_print
%xdefine _objectivepgp_BN_print_fp BORINGSSL_PREFIX %+ __objectivepgp_BN_print_fp
%xdefine _objectivepgp_BUF_MEM_append BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_append
%xdefine _objectivepgp_BUF_MEM_free BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_free
%xdefine _objectivepgp_BUF_MEM_grow BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_grow
%xdefine _objectivepgp_BUF_MEM_grow_clean BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_grow_clean
%xdefine _objectivepgp_BUF_MEM_new BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_new
%xdefine _objectivepgp_BUF_MEM_reserve BORINGSSL_PREFIX %+ __objectivepgp_BUF_MEM_reserve
%xdefine _objectivepgp_BUF_memdup BORINGSSL_PREFIX %+ __objectivepgp_BUF_memdup
%xdefine _objectivepgp_BUF_strdup BORINGSSL_PREFIX %+ __objectivepgp_BUF_strdup
%xdefine _objectivepgp_BUF_strlcat BORINGSSL_PREFIX %+ __objectivepgp_BUF_strlcat
%xdefine _objectivepgp_BUF_strlcpy BORINGSSL_PREFIX %+ __objectivepgp_BUF_strlcpy
%xdefine _objectivepgp_BUF_strndup BORINGSSL_PREFIX %+ __objectivepgp_BUF_strndup
%xdefine _objectivepgp_BUF_strnlen BORINGSSL_PREFIX %+ __objectivepgp_BUF_strnlen
%xdefine _objectivepgp_CBB_finish_i2d BORINGSSL_PREFIX %+ __objectivepgp_CBB_finish_i2d
%xdefine _objectivepgp_CBS_asn1_ber_to_der BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_ber_to_der
%xdefine _objectivepgp_CBS_get_asn1_implicit_string BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_implicit_string
%xdefine _objectivepgp_CBB_add_asn1 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1
%xdefine _objectivepgp_CBB_add_asn1_bool BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_bool
%xdefine _objectivepgp_CBB_add_asn1_octet_string BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_octet_string
%xdefine _objectivepgp_CBB_add_asn1_oid_from_text BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_oid_from_text
%xdefine _objectivepgp_CBB_add_asn1_uint64 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_asn1_uint64
%xdefine _objectivepgp_CBB_add_bytes BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_bytes
%xdefine _objectivepgp_CBB_add_space BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_space
%xdefine _objectivepgp_CBB_add_u16 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u16
%xdefine _objectivepgp_CBB_add_u16_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u16_length_prefixed
%xdefine _objectivepgp_CBB_add_u24 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u24
%xdefine _objectivepgp_CBB_add_u24_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u24_length_prefixed
%xdefine _objectivepgp_CBB_add_u32 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u32
%xdefine _objectivepgp_CBB_add_u64 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u64
%xdefine _objectivepgp_CBB_add_u8 BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u8
%xdefine _objectivepgp_CBB_add_u8_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBB_add_u8_length_prefixed
%xdefine _objectivepgp_CBB_cleanup BORINGSSL_PREFIX %+ __objectivepgp_CBB_cleanup
%xdefine _objectivepgp_CBB_data BORINGSSL_PREFIX %+ __objectivepgp_CBB_data
%xdefine _objectivepgp_CBB_did_write BORINGSSL_PREFIX %+ __objectivepgp_CBB_did_write
%xdefine _objectivepgp_CBB_discard_child BORINGSSL_PREFIX %+ __objectivepgp_CBB_discard_child
%xdefine _objectivepgp_CBB_finish BORINGSSL_PREFIX %+ __objectivepgp_CBB_finish
%xdefine _objectivepgp_CBB_flush BORINGSSL_PREFIX %+ __objectivepgp_CBB_flush
%xdefine _objectivepgp_CBB_flush_asn1_set_of BORINGSSL_PREFIX %+ __objectivepgp_CBB_flush_asn1_set_of
%xdefine _objectivepgp_CBB_init BORINGSSL_PREFIX %+ __objectivepgp_CBB_init
%xdefine _objectivepgp_CBB_init_fixed BORINGSSL_PREFIX %+ __objectivepgp_CBB_init_fixed
%xdefine _objectivepgp_CBB_len BORINGSSL_PREFIX %+ __objectivepgp_CBB_len
%xdefine _objectivepgp_CBB_reserve BORINGSSL_PREFIX %+ __objectivepgp_CBB_reserve
%xdefine _objectivepgp_CBB_zero BORINGSSL_PREFIX %+ __objectivepgp_CBB_zero
%xdefine _objectivepgp_CBS_asn1_bitstring_has_bit BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_bitstring_has_bit
%xdefine _objectivepgp_CBS_asn1_oid_to_text BORINGSSL_PREFIX %+ __objectivepgp_CBS_asn1_oid_to_text
%xdefine _objectivepgp_CBS_contains_zero_byte BORINGSSL_PREFIX %+ __objectivepgp_CBS_contains_zero_byte
%xdefine _objectivepgp_CBS_copy_bytes BORINGSSL_PREFIX %+ __objectivepgp_CBS_copy_bytes
%xdefine _objectivepgp_CBS_data BORINGSSL_PREFIX %+ __objectivepgp_CBS_data
%xdefine _objectivepgp_CBS_get_any_asn1 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_asn1
%xdefine _objectivepgp_CBS_get_any_asn1_element BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_asn1_element
%xdefine _objectivepgp_CBS_get_any_ber_asn1_element BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_any_ber_asn1_element
%xdefine _objectivepgp_CBS_get_asn1 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1
%xdefine _objectivepgp_CBS_get_asn1_bool BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_bool
%xdefine _objectivepgp_CBS_get_asn1_element BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_element
%xdefine _objectivepgp_CBS_get_asn1_uint64 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_asn1_uint64
%xdefine _objectivepgp_CBS_get_bytes BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_bytes
%xdefine _objectivepgp_CBS_get_last_u8 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_last_u8
%xdefine _objectivepgp_CBS_get_optional_asn1 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1
%xdefine _objectivepgp_CBS_get_optional_asn1_bool BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_bool
%xdefine _objectivepgp_CBS_get_optional_asn1_octet_string BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_octet_string
%xdefine _objectivepgp_CBS_get_optional_asn1_uint64 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_optional_asn1_uint64
%xdefine _objectivepgp_CBS_get_u16 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u16
%xdefine _objectivepgp_CBS_get_u16_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u16_length_prefixed
%xdefine _objectivepgp_CBS_get_u24 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u24
%xdefine _objectivepgp_CBS_get_u24_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u24_length_prefixed
%xdefine _objectivepgp_CBS_get_u32 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u32
%xdefine _objectivepgp_CBS_get_u64 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u64
%xdefine _objectivepgp_CBS_get_u8 BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u8
%xdefine _objectivepgp_CBS_get_u8_length_prefixed BORINGSSL_PREFIX %+ __objectivepgp_CBS_get_u8_length_prefixed
%xdefine _objectivepgp_CBS_init BORINGSSL_PREFIX %+ __objectivepgp_CBS_init
%xdefine _objectivepgp_CBS_is_valid_asn1_bitstring BORINGSSL_PREFIX %+ __objectivepgp_CBS_is_valid_asn1_bitstring
%xdefine _objectivepgp_CBS_len BORINGSSL_PREFIX %+ __objectivepgp_CBS_len
%xdefine _objectivepgp_CBS_mem_equal BORINGSSL_PREFIX %+ __objectivepgp_CBS_mem_equal
%xdefine _objectivepgp_CBS_peek_asn1_tag BORINGSSL_PREFIX %+ __objectivepgp_CBS_peek_asn1_tag
%xdefine _objectivepgp_CBS_skip BORINGSSL_PREFIX %+ __objectivepgp_CBS_skip
%xdefine _objectivepgp_CBS_stow BORINGSSL_PREFIX %+ __objectivepgp_CBS_stow
%xdefine _objectivepgp_CBS_strdup BORINGSSL_PREFIX %+ __objectivepgp_CBS_strdup
%xdefine _objectivepgp_cbb_add_latin1 BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_latin1
%xdefine _objectivepgp_cbb_add_ucs2_be BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_ucs2_be
%xdefine _objectivepgp_cbb_add_utf32_be BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_utf32_be
%xdefine _objectivepgp_cbb_add_utf8 BORINGSSL_PREFIX %+ __objectivepgp_cbb_add_utf8
%xdefine _objectivepgp_cbb_get_utf8_len BORINGSSL_PREFIX %+ __objectivepgp_cbb_get_utf8_len
%xdefine _objectivepgp_cbs_get_latin1 BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_latin1
%xdefine _objectivepgp_cbs_get_ucs2_be BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_ucs2_be
%xdefine _objectivepgp_cbs_get_utf32_be BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_utf32_be
%xdefine _objectivepgp_cbs_get_utf8 BORINGSSL_PREFIX %+ __objectivepgp_cbs_get_utf8
%xdefine _objectivepgp_CRYPTO_chacha_20 BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_chacha_20
%xdefine _objectivepgp_CRYPTO_hchacha20 BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_hchacha20
%xdefine _objectivepgp_EVP_get_cipherbyname BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_cipherbyname
%xdefine _objectivepgp_EVP_get_cipherbynid BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_cipherbynid
%xdefine _objectivepgp_EVP_BytesToKey BORINGSSL_PREFIX %+ __objectivepgp_EVP_BytesToKey
%xdefine _objectivepgp_EVP_aead_aes_128_ccm_bluetooth BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ccm_bluetooth
%xdefine _objectivepgp_EVP_aead_aes_128_ccm_bluetooth_8 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ccm_bluetooth_8
%xdefine _objectivepgp_EVP_aead_aes_128_ctr_hmac_sha256 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_ctr_hmac_sha256
%xdefine _objectivepgp_EVP_aead_aes_256_ctr_hmac_sha256 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_ctr_hmac_sha256
%xdefine _objectivepgp_EVP_aead_aes_128_gcm_siv BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_gcm_siv
%xdefine _objectivepgp_EVP_aead_aes_256_gcm_siv BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_gcm_siv
%xdefine _objectivepgp_EVP_aead_chacha20_poly1305 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_chacha20_poly1305
%xdefine _objectivepgp_EVP_aead_xchacha20_poly1305 BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_xchacha20_poly1305
%xdefine _objectivepgp_EVP_enc_null BORINGSSL_PREFIX %+ __objectivepgp_EVP_enc_null
%xdefine _objectivepgp_EVP_rc2_40_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc2_40_cbc
%xdefine _objectivepgp_EVP_rc2_cbc BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc2_cbc
%xdefine _objectivepgp_EVP_rc4 BORINGSSL_PREFIX %+ __objectivepgp_EVP_rc4
%xdefine _objectivepgp_EVP_aead_aes_128_cbc_sha1_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls
%xdefine _objectivepgp_EVP_aead_aes_128_cbc_sha1_tls_implicit_iv BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha1_tls_implicit_iv
%xdefine _objectivepgp_EVP_aead_aes_128_cbc_sha256_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_128_cbc_sha256_tls
%xdefine _objectivepgp_EVP_aead_aes_256_cbc_sha1_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls
%xdefine _objectivepgp_EVP_aead_aes_256_cbc_sha1_tls_implicit_iv BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha1_tls_implicit_iv
%xdefine _objectivepgp_EVP_aead_aes_256_cbc_sha256_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha256_tls
%xdefine _objectivepgp_EVP_aead_aes_256_cbc_sha384_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_aes_256_cbc_sha384_tls
%xdefine _objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls
%xdefine _objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv
%xdefine _objectivepgp_EVP_aead_null_sha1_tls BORINGSSL_PREFIX %+ __objectivepgp_EVP_aead_null_sha1_tls
%xdefine _objectivepgp_EVP_tls_cbc_copy_mac BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_copy_mac
%xdefine _objectivepgp_EVP_tls_cbc_digest_record BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_digest_record
%xdefine _objectivepgp_EVP_tls_cbc_record_digest_supported BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_record_digest_supported
%xdefine _objectivepgp_EVP_tls_cbc_remove_padding BORINGSSL_PREFIX %+ __objectivepgp_EVP_tls_cbc_remove_padding
%xdefine _objectivepgp_AES_CMAC BORINGSSL_PREFIX %+ __objectivepgp_AES_CMAC
%xdefine _objectivepgp_CMAC_CTX_copy BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_copy
%xdefine _objectivepgp_CMAC_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_free
%xdefine _objectivepgp_CMAC_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_CMAC_CTX_new
%xdefine _objectivepgp_CMAC_Final BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Final
%xdefine _objectivepgp_CMAC_Init BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Init
%xdefine _objectivepgp_CMAC_Reset BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Reset
%xdefine _objectivepgp_CMAC_Update BORINGSSL_PREFIX %+ __objectivepgp_CMAC_Update
%xdefine _objectivepgp_CONF_VALUE_new BORINGSSL_PREFIX %+ __objectivepgp_CONF_VALUE_new
%xdefine _objectivepgp_CONF_modules_free BORINGSSL_PREFIX %+ __objectivepgp_CONF_modules_free
%xdefine _objectivepgp_CONF_modules_load_file BORINGSSL_PREFIX %+ __objectivepgp_CONF_modules_load_file
%xdefine _objectivepgp_CONF_parse_list BORINGSSL_PREFIX %+ __objectivepgp_CONF_parse_list
%xdefine _objectivepgp_NCONF_free BORINGSSL_PREFIX %+ __objectivepgp_NCONF_free
%xdefine _objectivepgp_NCONF_get_section BORINGSSL_PREFIX %+ __objectivepgp_NCONF_get_section
%xdefine _objectivepgp_NCONF_get_string BORINGSSL_PREFIX %+ __objectivepgp_NCONF_get_string
%xdefine _objectivepgp_NCONF_load BORINGSSL_PREFIX %+ __objectivepgp_NCONF_load
%xdefine _objectivepgp_NCONF_load_bio BORINGSSL_PREFIX %+ __objectivepgp_NCONF_load_bio
%xdefine _objectivepgp_NCONF_new BORINGSSL_PREFIX %+ __objectivepgp_NCONF_new
%xdefine _objectivepgp_OPENSSL_config BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_config
%xdefine _objectivepgp_OPENSSL_no_config BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_no_config
%xdefine _objectivepgp_OPENSSL_cpuid_setup BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cpuid_setup
%xdefine _objectivepgp_CRYPTO_has_asm BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_has_asm
%xdefine _objectivepgp_CRYPTO_is_confidential_build BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_is_confidential_build
%xdefine _objectivepgp_CRYPTO_library_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_library_init
%xdefine _objectivepgp_CRYPTO_malloc_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_malloc_init
%xdefine _objectivepgp_ENGINE_load_builtin_engines BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_load_builtin_engines
%xdefine _objectivepgp_ENGINE_register_all_complete BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_register_all_complete
%xdefine _objectivepgp_OPENSSL_cleanup BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cleanup
%xdefine _objectivepgp_OPENSSL_ia32cap_P BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_ia32cap_P
%xdefine _objectivepgp_OPENSSL_init_crypto BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_init_crypto
%xdefine _objectivepgp_OPENSSL_load_builtin_modules BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_load_builtin_modules
%xdefine _objectivepgp_OPENSSL_malloc_init BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_malloc_init
%xdefine _objectivepgp_OpenSSL_version BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_version
%xdefine _objectivepgp_OpenSSL_version_num BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_version_num
%xdefine _objectivepgp_SSLeay BORINGSSL_PREFIX %+ __objectivepgp_SSLeay
%xdefine _objectivepgp_SSLeay_version BORINGSSL_PREFIX %+ __objectivepgp_SSLeay_version
%xdefine _objectivepgp_SPAKE2_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_CTX_free
%xdefine _objectivepgp_SPAKE2_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_CTX_new
%xdefine _objectivepgp_SPAKE2_generate_msg BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_generate_msg
%xdefine _objectivepgp_SPAKE2_process_msg BORINGSSL_PREFIX %+ __objectivepgp_SPAKE2_process_msg
%xdefine _objectivepgp_DH_compute_key BORINGSSL_PREFIX %+ __objectivepgp_DH_compute_key
%xdefine _objectivepgp_DH_free BORINGSSL_PREFIX %+ __objectivepgp_DH_free
%xdefine _objectivepgp_DH_generate_key BORINGSSL_PREFIX %+ __objectivepgp_DH_generate_key
%xdefine _objectivepgp_DH_generate_parameters_ex BORINGSSL_PREFIX %+ __objectivepgp_DH_generate_parameters_ex
%xdefine _objectivepgp_DH_get0_key BORINGSSL_PREFIX %+ __objectivepgp_DH_get0_key
%xdefine _objectivepgp_DH_get0_pqg BORINGSSL_PREFIX %+ __objectivepgp_DH_get0_pqg
%xdefine _objectivepgp_DH_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_DH_get_ex_data
%xdefine _objectivepgp_DH_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_DH_get_ex_new_index
%xdefine _objectivepgp_DH_new BORINGSSL_PREFIX %+ __objectivepgp_DH_new
%xdefine _objectivepgp_DH_num_bits BORINGSSL_PREFIX %+ __objectivepgp_DH_num_bits
%xdefine _objectivepgp_DH_set0_key BORINGSSL_PREFIX %+ __objectivepgp_DH_set0_key
%xdefine _objectivepgp_DH_set0_pqg BORINGSSL_PREFIX %+ __objectivepgp_DH_set0_pqg
%xdefine _objectivepgp_DH_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_DH_set_ex_data
%xdefine _objectivepgp_DH_size BORINGSSL_PREFIX %+ __objectivepgp_DH_size
%xdefine _objectivepgp_DH_up_ref BORINGSSL_PREFIX %+ __objectivepgp_DH_up_ref
%xdefine _objectivepgp_DHparams_dup BORINGSSL_PREFIX %+ __objectivepgp_DHparams_dup
%xdefine _objectivepgp_BN_get_rfc3526_prime_1536 BORINGSSL_PREFIX %+ __objectivepgp_BN_get_rfc3526_prime_1536
%xdefine _objectivepgp_DH_check BORINGSSL_PREFIX %+ __objectivepgp_DH_check
%xdefine _objectivepgp_DH_check_pub_key BORINGSSL_PREFIX %+ __objectivepgp_DH_check_pub_key
%xdefine _objectivepgp_DH_marshal_parameters BORINGSSL_PREFIX %+ __objectivepgp_DH_marshal_parameters
%xdefine _objectivepgp_DH_parse_parameters BORINGSSL_PREFIX %+ __objectivepgp_DH_parse_parameters
%xdefine _objectivepgp_d2i_DHparams BORINGSSL_PREFIX %+ __objectivepgp_d2i_DHparams
%xdefine _objectivepgp_i2d_DHparams BORINGSSL_PREFIX %+ __objectivepgp_i2d_DHparams
%xdefine _objectivepgp_EVP_get_digestbyname BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbyname
%xdefine _objectivepgp_EVP_get_digestbynid BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbynid
%xdefine _objectivepgp_EVP_get_digestbyobj BORINGSSL_PREFIX %+ __objectivepgp_EVP_get_digestbyobj
%xdefine _objectivepgp_EVP_marshal_digest_algorithm BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_digest_algorithm
%xdefine _objectivepgp_EVP_parse_digest_algorithm BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_digest_algorithm
%xdefine _objectivepgp_DSA_SIG_free BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_free
%xdefine _objectivepgp_DSA_SIG_new BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_new
%xdefine _objectivepgp_DSA_check_signature BORINGSSL_PREFIX %+ __objectivepgp_DSA_check_signature
%xdefine _objectivepgp_DSA_do_check_signature BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_check_signature
%xdefine _objectivepgp_DSA_do_sign BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_sign
%xdefine _objectivepgp_DSA_do_verify BORINGSSL_PREFIX %+ __objectivepgp_DSA_do_verify
%xdefine _objectivepgp_DSA_dup_DH BORINGSSL_PREFIX %+ __objectivepgp_DSA_dup_DH
%xdefine _objectivepgp_DSA_free BORINGSSL_PREFIX %+ __objectivepgp_DSA_free
%xdefine _objectivepgp_DSA_generate_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_generate_key
%xdefine _objectivepgp_DSA_generate_parameters_ex BORINGSSL_PREFIX %+ __objectivepgp_DSA_generate_parameters_ex
%xdefine _objectivepgp_DSA_get0_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_get0_key
%xdefine _objectivepgp_DSA_get0_pqg BORINGSSL_PREFIX %+ __objectivepgp_DSA_get0_pqg
%xdefine _objectivepgp_DSA_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_DSA_get_ex_data
%xdefine _objectivepgp_DSA_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_DSA_get_ex_new_index
%xdefine _objectivepgp_DSA_new BORINGSSL_PREFIX %+ __objectivepgp_DSA_new
%xdefine _objectivepgp_DSA_set0_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_set0_key
%xdefine _objectivepgp_DSA_set0_pqg BORINGSSL_PREFIX %+ __objectivepgp_DSA_set0_pqg
%xdefine _objectivepgp_DSA_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_DSA_set_ex_data
%xdefine _objectivepgp_DSA_sign BORINGSSL_PREFIX %+ __objectivepgp_DSA_sign
%xdefine _objectivepgp_DSA_size BORINGSSL_PREFIX %+ __objectivepgp_DSA_size
%xdefine _objectivepgp_DSA_up_ref BORINGSSL_PREFIX %+ __objectivepgp_DSA_up_ref
%xdefine _objectivepgp_DSA_verify BORINGSSL_PREFIX %+ __objectivepgp_DSA_verify
%xdefine _objectivepgp_DSAparams_dup BORINGSSL_PREFIX %+ __objectivepgp_DSAparams_dup
%xdefine _objectivepgp_DSA_SIG_marshal BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_marshal
%xdefine _objectivepgp_DSA_SIG_parse BORINGSSL_PREFIX %+ __objectivepgp_DSA_SIG_parse
%xdefine _objectivepgp_DSA_marshal_parameters BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_parameters
%xdefine _objectivepgp_DSA_marshal_private_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_private_key
%xdefine _objectivepgp_DSA_marshal_public_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_marshal_public_key
%xdefine _objectivepgp_DSA_parse_parameters BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_parameters
%xdefine _objectivepgp_DSA_parse_private_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_private_key
%xdefine _objectivepgp_DSA_parse_public_key BORINGSSL_PREFIX %+ __objectivepgp_DSA_parse_public_key
%xdefine _objectivepgp_d2i_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey
%xdefine _objectivepgp_d2i_DSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPublicKey
%xdefine _objectivepgp_d2i_DSA_SIG BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_SIG
%xdefine _objectivepgp_d2i_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAparams
%xdefine _objectivepgp_i2d_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey
%xdefine _objectivepgp_i2d_DSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPublicKey
%xdefine _objectivepgp_i2d_DSA_SIG BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_SIG
%xdefine _objectivepgp_i2d_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAparams
%xdefine _objectivepgp_ECDH_compute_key BORINGSSL_PREFIX %+ __objectivepgp_ECDH_compute_key
%xdefine _objectivepgp_ECDSA_SIG_from_bytes BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_from_bytes
%xdefine _objectivepgp_ECDSA_SIG_marshal BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_marshal
%xdefine _objectivepgp_ECDSA_SIG_max_len BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_max_len
%xdefine _objectivepgp_ECDSA_SIG_parse BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_parse
%xdefine _objectivepgp_ECDSA_SIG_to_bytes BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_SIG_to_bytes
%xdefine _objectivepgp_ECDSA_sign BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_sign
%xdefine _objectivepgp_ECDSA_size BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_size
%xdefine _objectivepgp_ECDSA_verify BORINGSSL_PREFIX %+ __objectivepgp_ECDSA_verify
%xdefine _objectivepgp_d2i_ECDSA_SIG BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECDSA_SIG
%xdefine _objectivepgp_i2d_ECDSA_SIG BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECDSA_SIG
%xdefine _objectivepgp_EC_KEY_marshal_curve_name BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_marshal_curve_name
%xdefine _objectivepgp_EC_KEY_marshal_private_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_marshal_private_key
%xdefine _objectivepgp_EC_KEY_parse_curve_name BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_curve_name
%xdefine _objectivepgp_EC_KEY_parse_parameters BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_parameters
%xdefine _objectivepgp_EC_KEY_parse_private_key BORINGSSL_PREFIX %+ __objectivepgp_EC_KEY_parse_private_key
%xdefine _objectivepgp_EC_POINT_point2cbb BORINGSSL_PREFIX %+ __objectivepgp_EC_POINT_point2cbb
%xdefine _objectivepgp_d2i_ECParameters BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECParameters
%xdefine _objectivepgp_d2i_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey
%xdefine _objectivepgp_i2d_ECParameters BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECParameters
%xdefine _objectivepgp_i2d_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey
%xdefine _objectivepgp_i2o_ECPublicKey BORINGSSL_PREFIX %+ __objectivepgp_i2o_ECPublicKey
%xdefine _objectivepgp_o2i_ECPublicKey BORINGSSL_PREFIX %+ __objectivepgp_o2i_ECPublicKey
%xdefine _objectivepgp_ERR_SAVE_STATE_free BORINGSSL_PREFIX %+ __objectivepgp_ERR_SAVE_STATE_free
%xdefine _objectivepgp_ERR_add_error_data BORINGSSL_PREFIX %+ __objectivepgp_ERR_add_error_data
%xdefine _objectivepgp_ERR_add_error_dataf BORINGSSL_PREFIX %+ __objectivepgp_ERR_add_error_dataf
%xdefine _objectivepgp_ERR_clear_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_clear_error
%xdefine _objectivepgp_ERR_clear_system_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_clear_system_error
%xdefine _objectivepgp_ERR_error_string BORINGSSL_PREFIX %+ __objectivepgp_ERR_error_string
%xdefine _objectivepgp_ERR_error_string_n BORINGSSL_PREFIX %+ __objectivepgp_ERR_error_string_n
%xdefine _objectivepgp_ERR_free_strings BORINGSSL_PREFIX %+ __objectivepgp_ERR_free_strings
%xdefine _objectivepgp_ERR_func_error_string BORINGSSL_PREFIX %+ __objectivepgp_ERR_func_error_string
%xdefine _objectivepgp_ERR_get_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error
%xdefine _objectivepgp_ERR_get_error_line BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error_line
%xdefine _objectivepgp_ERR_get_error_line_data BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_error_line_data
%xdefine _objectivepgp_ERR_get_next_error_library BORINGSSL_PREFIX %+ __objectivepgp_ERR_get_next_error_library
%xdefine _objectivepgp_ERR_lib_error_string BORINGSSL_PREFIX %+ __objectivepgp_ERR_lib_error_string
%xdefine _objectivepgp_ERR_load_BIO_strings BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_BIO_strings
%xdefine _objectivepgp_ERR_load_ERR_strings BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_ERR_strings
%xdefine _objectivepgp_ERR_load_RAND_strings BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_RAND_strings
%xdefine _objectivepgp_ERR_load_crypto_strings BORINGSSL_PREFIX %+ __objectivepgp_ERR_load_crypto_strings
%xdefine _objectivepgp_ERR_peek_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error
%xdefine _objectivepgp_ERR_peek_error_line BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error_line
%xdefine _objectivepgp_ERR_peek_error_line_data BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_error_line_data
%xdefine _objectivepgp_ERR_peek_last_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error
%xdefine _objectivepgp_ERR_peek_last_error_line BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error_line
%xdefine _objectivepgp_ERR_peek_last_error_line_data BORINGSSL_PREFIX %+ __objectivepgp_ERR_peek_last_error_line_data
%xdefine _objectivepgp_ERR_pop_to_mark BORINGSSL_PREFIX %+ __objectivepgp_ERR_pop_to_mark
%xdefine _objectivepgp_ERR_print_errors_cb BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors_cb
%xdefine _objectivepgp_ERR_print_errors_fp BORINGSSL_PREFIX %+ __objectivepgp_ERR_print_errors_fp
%xdefine _objectivepgp_ERR_put_error BORINGSSL_PREFIX %+ __objectivepgp_ERR_put_error
%xdefine _objectivepgp_ERR_reason_error_string BORINGSSL_PREFIX %+ __objectivepgp_ERR_reason_error_string
%xdefine _objectivepgp_ERR_remove_state BORINGSSL_PREFIX %+ __objectivepgp_ERR_remove_state
%xdefine _objectivepgp_ERR_remove_thread_state BORINGSSL_PREFIX %+ __objectivepgp_ERR_remove_thread_state
%xdefine _objectivepgp_ERR_restore_state BORINGSSL_PREFIX %+ __objectivepgp_ERR_restore_state
%xdefine _objectivepgp_ERR_save_state BORINGSSL_PREFIX %+ __objectivepgp_ERR_save_state
%xdefine _objectivepgp_ERR_set_mark BORINGSSL_PREFIX %+ __objectivepgp_ERR_set_mark
%xdefine _objectivepgp_kOpenSSLReasonStringData BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonStringData
%xdefine _objectivepgp_kOpenSSLReasonValues BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonValues
%xdefine _objectivepgp_kOpenSSLReasonValuesLen BORINGSSL_PREFIX %+ __objectivepgp_kOpenSSLReasonValuesLen
%xdefine _objectivepgp_ENGINE_free BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_free
%xdefine _objectivepgp_ENGINE_get_ECDSA_method BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_get_ECDSA_method
%xdefine _objectivepgp_ENGINE_get_RSA_method BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_get_RSA_method
%xdefine _objectivepgp_ENGINE_new BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_new
%xdefine _objectivepgp_ENGINE_set_ECDSA_method BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_set_ECDSA_method
%xdefine _objectivepgp_ENGINE_set_RSA_method BORINGSSL_PREFIX %+ __objectivepgp_ENGINE_set_RSA_method
%xdefine _objectivepgp_METHOD_ref BORINGSSL_PREFIX %+ __objectivepgp_METHOD_ref
%xdefine _objectivepgp_METHOD_unref BORINGSSL_PREFIX %+ __objectivepgp_METHOD_unref
%xdefine _objectivepgp_EVP_DigestSign BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSign
%xdefine _objectivepgp_EVP_DigestSignFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignFinal
%xdefine _objectivepgp_EVP_DigestSignInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignInit
%xdefine _objectivepgp_EVP_DigestSignUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestSignUpdate
%xdefine _objectivepgp_EVP_DigestVerify BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerify
%xdefine _objectivepgp_EVP_DigestVerifyFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyFinal
%xdefine _objectivepgp_EVP_DigestVerifyInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyInit
%xdefine _objectivepgp_EVP_DigestVerifyUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_DigestVerifyUpdate
%xdefine _objectivepgp_EVP_PKEY_CTX_get_signature_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_signature_md
%xdefine _objectivepgp_EVP_PKEY_CTX_set_signature_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_signature_md
%xdefine _objectivepgp_EVP_PKEY_assign BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign
%xdefine _objectivepgp_EVP_PKEY_assign_DSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_DSA
%xdefine _objectivepgp_EVP_PKEY_assign_EC_KEY BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_EC_KEY
%xdefine _objectivepgp_EVP_PKEY_assign_RSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_assign_RSA
%xdefine _objectivepgp_EVP_PKEY_base_id BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_base_id
%xdefine _objectivepgp_EVP_PKEY_bits BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_bits
%xdefine _objectivepgp_EVP_PKEY_cmp BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_cmp
%xdefine _objectivepgp_EVP_PKEY_cmp_parameters BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_cmp_parameters
%xdefine _objectivepgp_EVP_PKEY_copy_parameters BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_copy_parameters
%xdefine _objectivepgp_EVP_PKEY_free BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_free
%xdefine _objectivepgp_EVP_PKEY_get0_DH BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_DH
%xdefine _objectivepgp_EVP_PKEY_get0_DSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_DSA
%xdefine _objectivepgp_EVP_PKEY_get0_EC_KEY BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_EC_KEY
%xdefine _objectivepgp_EVP_PKEY_get0_RSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get0_RSA
%xdefine _objectivepgp_EVP_PKEY_get1_DH BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_DH
%xdefine _objectivepgp_EVP_PKEY_get1_DSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_DSA
%xdefine _objectivepgp_EVP_PKEY_get1_EC_KEY BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_EC_KEY
%xdefine _objectivepgp_EVP_PKEY_get1_RSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_RSA
%xdefine _objectivepgp_EVP_PKEY_get_raw_private_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get_raw_private_key
%xdefine _objectivepgp_EVP_PKEY_get_raw_public_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get_raw_public_key
%xdefine _objectivepgp_EVP_PKEY_id BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_id
%xdefine _objectivepgp_EVP_PKEY_is_opaque BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_is_opaque
%xdefine _objectivepgp_EVP_PKEY_missing_parameters BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_missing_parameters
%xdefine _objectivepgp_EVP_PKEY_new BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new
%xdefine _objectivepgp_EVP_PKEY_new_raw_private_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new_raw_private_key
%xdefine _objectivepgp_EVP_PKEY_new_raw_public_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_new_raw_public_key
%xdefine _objectivepgp_EVP_PKEY_set1_DSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_DSA
%xdefine _objectivepgp_EVP_PKEY_set1_EC_KEY BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_EC_KEY
%xdefine _objectivepgp_EVP_PKEY_set1_RSA BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_RSA
%xdefine _objectivepgp_EVP_PKEY_set_type BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set_type
%xdefine _objectivepgp_EVP_PKEY_size BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_size
%xdefine _objectivepgp_EVP_PKEY_type BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_type
%xdefine _objectivepgp_EVP_PKEY_up_ref BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_up_ref
%xdefine _objectivepgp_EVP_cleanup BORINGSSL_PREFIX %+ __objectivepgp_EVP_cleanup
%xdefine _objectivepgp_OPENSSL_add_all_algorithms_conf BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_add_all_algorithms_conf
%xdefine _objectivepgp_OpenSSL_add_all_algorithms BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_algorithms
%xdefine _objectivepgp_OpenSSL_add_all_ciphers BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_ciphers
%xdefine _objectivepgp_OpenSSL_add_all_digests BORINGSSL_PREFIX %+ __objectivepgp_OpenSSL_add_all_digests
%xdefine _objectivepgp_EVP_marshal_private_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_private_key
%xdefine _objectivepgp_EVP_marshal_public_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_marshal_public_key
%xdefine _objectivepgp_EVP_parse_private_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_private_key
%xdefine _objectivepgp_EVP_parse_public_key BORINGSSL_PREFIX %+ __objectivepgp_EVP_parse_public_key
%xdefine _objectivepgp_d2i_AutoPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_AutoPrivateKey
%xdefine _objectivepgp_d2i_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey
%xdefine _objectivepgp_d2i_PublicKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_PublicKey
%xdefine _objectivepgp_i2d_PublicKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_PublicKey
%xdefine _objectivepgp_EVP_PKEY_CTX_ctrl BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_ctrl
%xdefine _objectivepgp_EVP_PKEY_CTX_dup BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_dup
%xdefine _objectivepgp_EVP_PKEY_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_free
%xdefine _objectivepgp_EVP_PKEY_CTX_get0_pkey BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get0_pkey
%xdefine _objectivepgp_EVP_PKEY_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_new
%xdefine _objectivepgp_EVP_PKEY_CTX_new_id BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_new_id
%xdefine _objectivepgp_EVP_PKEY_decrypt BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_decrypt
%xdefine _objectivepgp_EVP_PKEY_decrypt_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_decrypt_init
%xdefine _objectivepgp_EVP_PKEY_derive BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive
%xdefine _objectivepgp_EVP_PKEY_derive_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive_init
%xdefine _objectivepgp_EVP_PKEY_derive_set_peer BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_derive_set_peer
%xdefine _objectivepgp_EVP_PKEY_encrypt BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_encrypt
%xdefine _objectivepgp_EVP_PKEY_encrypt_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_encrypt_init
%xdefine _objectivepgp_EVP_PKEY_keygen BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_keygen
%xdefine _objectivepgp_EVP_PKEY_keygen_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_keygen_init
%xdefine _objectivepgp_EVP_PKEY_paramgen BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_paramgen
%xdefine _objectivepgp_EVP_PKEY_paramgen_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_paramgen_init
%xdefine _objectivepgp_EVP_PKEY_sign BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_sign
%xdefine _objectivepgp_EVP_PKEY_sign_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_sign_init
%xdefine _objectivepgp_EVP_PKEY_verify BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify
%xdefine _objectivepgp_EVP_PKEY_verify_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_init
%xdefine _objectivepgp_EVP_PKEY_verify_recover BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_recover
%xdefine _objectivepgp_EVP_PKEY_verify_recover_init BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_verify_recover_init
%xdefine _objectivepgp_dsa_asn1_meth BORINGSSL_PREFIX %+ __objectivepgp_dsa_asn1_meth
%xdefine _objectivepgp_EVP_PKEY_CTX_set_ec_param_enc BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_ec_param_enc
%xdefine _objectivepgp_EVP_PKEY_CTX_set_ec_paramgen_curve_nid BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_ec_paramgen_curve_nid
%xdefine _objectivepgp_ec_pkey_meth BORINGSSL_PREFIX %+ __objectivepgp_ec_pkey_meth
%xdefine _objectivepgp_ec_asn1_meth BORINGSSL_PREFIX %+ __objectivepgp_ec_asn1_meth
%xdefine _objectivepgp_ed25519_pkey_meth BORINGSSL_PREFIX %+ __objectivepgp_ed25519_pkey_meth
%xdefine _objectivepgp_ed25519_asn1_meth BORINGSSL_PREFIX %+ __objectivepgp_ed25519_asn1_meth
%xdefine _objectivepgp_EVP_PKEY_CTX_get0_rsa_oaep_label BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get0_rsa_oaep_label
%xdefine _objectivepgp_EVP_PKEY_CTX_get_rsa_mgf1_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_mgf1_md
%xdefine _objectivepgp_EVP_PKEY_CTX_get_rsa_oaep_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_oaep_md
%xdefine _objectivepgp_EVP_PKEY_CTX_get_rsa_padding BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_padding
%xdefine _objectivepgp_EVP_PKEY_CTX_get_rsa_pss_saltlen BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_get_rsa_pss_saltlen
%xdefine _objectivepgp_EVP_PKEY_CTX_set0_rsa_oaep_label BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set0_rsa_oaep_label
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_bits BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_bits
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_pubexp BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_keygen_pubexp
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_mgf1_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_mgf1_md
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_oaep_md BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_oaep_md
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_padding BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_padding
%xdefine _objectivepgp_EVP_PKEY_CTX_set_rsa_pss_saltlen BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_CTX_set_rsa_pss_saltlen
%xdefine _objectivepgp_rsa_pkey_meth BORINGSSL_PREFIX %+ __objectivepgp_rsa_pkey_meth
%xdefine _objectivepgp_rsa_asn1_meth BORINGSSL_PREFIX %+ __objectivepgp_rsa_asn1_meth
%xdefine _objectivepgp_x25519_pkey_meth BORINGSSL_PREFIX %+ __objectivepgp_x25519_pkey_meth
%xdefine _objectivepgp_EVP_PKEY_get1_tls_encodedpoint BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_get1_tls_encodedpoint
%xdefine _objectivepgp_EVP_PKEY_set1_tls_encodedpoint BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_set1_tls_encodedpoint
%xdefine _objectivepgp_x25519_asn1_meth BORINGSSL_PREFIX %+ __objectivepgp_x25519_asn1_meth
%xdefine _objectivepgp_PKCS5_PBKDF2_HMAC BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_PBKDF2_HMAC
%xdefine _objectivepgp_PKCS5_PBKDF2_HMAC_SHA1 BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_PBKDF2_HMAC_SHA1
%xdefine _objectivepgp_EVP_PKEY_print_params BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_params
%xdefine _objectivepgp_EVP_PKEY_print_private BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_private
%xdefine _objectivepgp_EVP_PKEY_print_public BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY_print_public
%xdefine _objectivepgp_EVP_PBE_scrypt BORINGSSL_PREFIX %+ __objectivepgp_EVP_PBE_scrypt
%xdefine _objectivepgp_EVP_SignFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignFinal
%xdefine _objectivepgp_EVP_SignInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignInit
%xdefine _objectivepgp_EVP_SignInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignInit_ex
%xdefine _objectivepgp_EVP_SignUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_SignUpdate
%xdefine _objectivepgp_EVP_VerifyFinal BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyFinal
%xdefine _objectivepgp_EVP_VerifyInit BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyInit
%xdefine _objectivepgp_EVP_VerifyInit_ex BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyInit_ex
%xdefine _objectivepgp_EVP_VerifyUpdate BORINGSSL_PREFIX %+ __objectivepgp_EVP_VerifyUpdate
%xdefine _objectivepgp_CRYPTO_cleanup_all_ex_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_cleanup_all_ex_data
%xdefine _objectivepgp_CRYPTO_free_ex_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_free_ex_data
%xdefine _objectivepgp_CRYPTO_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_ex_data
%xdefine _objectivepgp_CRYPTO_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_ex_new_index
%xdefine _objectivepgp_CRYPTO_new_ex_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_new_ex_data
%xdefine _objectivepgp_CRYPTO_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_ex_data
%xdefine _objectivepgp_HKDF BORINGSSL_PREFIX %+ __objectivepgp_HKDF
%xdefine _objectivepgp_HKDF_expand BORINGSSL_PREFIX %+ __objectivepgp_HKDF_expand
%xdefine _objectivepgp_HKDF_extract BORINGSSL_PREFIX %+ __objectivepgp_HKDF_extract
%xdefine _objectivepgp_HRSS_decap BORINGSSL_PREFIX %+ __objectivepgp_HRSS_decap
%xdefine _objectivepgp_HRSS_encap BORINGSSL_PREFIX %+ __objectivepgp_HRSS_encap
%xdefine _objectivepgp_HRSS_generate_key BORINGSSL_PREFIX %+ __objectivepgp_HRSS_generate_key
%xdefine _objectivepgp_HRSS_marshal_public_key BORINGSSL_PREFIX %+ __objectivepgp_HRSS_marshal_public_key
%xdefine _objectivepgp_HRSS_parse_public_key BORINGSSL_PREFIX %+ __objectivepgp_HRSS_parse_public_key
%xdefine _objectivepgp_HRSS_poly2_rotr_consttime BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly2_rotr_consttime
%xdefine _objectivepgp_HRSS_poly3_invert BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly3_invert
%xdefine _objectivepgp_HRSS_poly3_mul BORINGSSL_PREFIX %+ __objectivepgp_HRSS_poly3_mul
%xdefine _objectivepgp_lh_delete BORINGSSL_PREFIX %+ __objectivepgp_lh_delete
%xdefine _objectivepgp_lh_doall_arg BORINGSSL_PREFIX %+ __objectivepgp_lh_doall_arg
%xdefine _objectivepgp_lh_free BORINGSSL_PREFIX %+ __objectivepgp_lh_free
%xdefine _objectivepgp_lh_insert BORINGSSL_PREFIX %+ __objectivepgp_lh_insert
%xdefine _objectivepgp_lh_new BORINGSSL_PREFIX %+ __objectivepgp_lh_new
%xdefine _objectivepgp_lh_num_items BORINGSSL_PREFIX %+ __objectivepgp_lh_num_items
%xdefine _objectivepgp_lh_retrieve BORINGSSL_PREFIX %+ __objectivepgp_lh_retrieve
%xdefine _objectivepgp_lh_retrieve_key BORINGSSL_PREFIX %+ __objectivepgp_lh_retrieve_key
%xdefine _objectivepgp_lh_strhash BORINGSSL_PREFIX %+ __objectivepgp_lh_strhash
%xdefine _objectivepgp_BIO_snprintf BORINGSSL_PREFIX %+ __objectivepgp_BIO_snprintf
%xdefine _objectivepgp_BIO_vsnprintf BORINGSSL_PREFIX %+ __objectivepgp_BIO_vsnprintf
%xdefine _objectivepgp_CRYPTO_memcmp BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_memcmp
%xdefine _objectivepgp_OPENSSL_cleanse BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_cleanse
%xdefine _objectivepgp_OPENSSL_clear_free BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_clear_free
%xdefine _objectivepgp_OPENSSL_free BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_free
%xdefine _objectivepgp_OPENSSL_hash32 BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_hash32
%xdefine _objectivepgp_OPENSSL_malloc BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_malloc
%xdefine _objectivepgp_OPENSSL_realloc BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_realloc
%xdefine _objectivepgp_OPENSSL_strcasecmp BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strcasecmp
%xdefine _objectivepgp_OPENSSL_strdup BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strdup
%xdefine _objectivepgp_OPENSSL_strncasecmp BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strncasecmp
%xdefine _objectivepgp_OPENSSL_strnlen BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_strnlen
%xdefine _objectivepgp_OPENSSL_tolower BORINGSSL_PREFIX %+ __objectivepgp_OPENSSL_tolower
%xdefine _objectivepgp_sdallocx BORINGSSL_PREFIX %+ __objectivepgp_sdallocx
%xdefine _objectivepgp_OBJ_cbs2nid BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cbs2nid
%xdefine _objectivepgp_OBJ_cleanup BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cleanup
%xdefine _objectivepgp_OBJ_cmp BORINGSSL_PREFIX %+ __objectivepgp_OBJ_cmp
%xdefine _objectivepgp_OBJ_create BORINGSSL_PREFIX %+ __objectivepgp_OBJ_create
%xdefine _objectivepgp_OBJ_dup BORINGSSL_PREFIX %+ __objectivepgp_OBJ_dup
%xdefine _objectivepgp_OBJ_get0_data BORINGSSL_PREFIX %+ __objectivepgp_OBJ_get0_data
%xdefine _objectivepgp_OBJ_length BORINGSSL_PREFIX %+ __objectivepgp_OBJ_length
%xdefine _objectivepgp_OBJ_ln2nid BORINGSSL_PREFIX %+ __objectivepgp_OBJ_ln2nid
%xdefine _objectivepgp_OBJ_nid2cbb BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2cbb
%xdefine _objectivepgp_OBJ_nid2ln BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2ln
%xdefine _objectivepgp_OBJ_nid2obj BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2obj
%xdefine _objectivepgp_OBJ_nid2sn BORINGSSL_PREFIX %+ __objectivepgp_OBJ_nid2sn
%xdefine _objectivepgp_OBJ_obj2nid BORINGSSL_PREFIX %+ __objectivepgp_OBJ_obj2nid
%xdefine _objectivepgp_OBJ_obj2txt BORINGSSL_PREFIX %+ __objectivepgp_OBJ_obj2txt
%xdefine _objectivepgp_OBJ_sn2nid BORINGSSL_PREFIX %+ __objectivepgp_OBJ_sn2nid
%xdefine _objectivepgp_OBJ_txt2nid BORINGSSL_PREFIX %+ __objectivepgp_OBJ_txt2nid
%xdefine _objectivepgp_OBJ_txt2obj BORINGSSL_PREFIX %+ __objectivepgp_OBJ_txt2obj
%xdefine _objectivepgp_OBJ_find_sigid_algs BORINGSSL_PREFIX %+ __objectivepgp_OBJ_find_sigid_algs
%xdefine _objectivepgp_OBJ_find_sigid_by_algs BORINGSSL_PREFIX %+ __objectivepgp_OBJ_find_sigid_by_algs
%xdefine _objectivepgp_PEM_read_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSAPrivateKey
%xdefine _objectivepgp_PEM_read_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSA_PUBKEY
%xdefine _objectivepgp_PEM_read_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DSAparams
%xdefine _objectivepgp_PEM_read_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_ECPrivateKey
%xdefine _objectivepgp_PEM_read_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_EC_PUBKEY
%xdefine _objectivepgp_PEM_read_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS7
%xdefine _objectivepgp_PEM_read_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PUBKEY
%xdefine _objectivepgp_PEM_read_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSAPrivateKey
%xdefine _objectivepgp_PEM_read_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSAPublicKey
%xdefine _objectivepgp_PEM_read_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_RSA_PUBKEY
%xdefine _objectivepgp_PEM_read_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_CRL
%xdefine _objectivepgp_PEM_read_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_REQ
%xdefine _objectivepgp_PEM_read_bio_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSAPrivateKey
%xdefine _objectivepgp_PEM_read_bio_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSA_PUBKEY
%xdefine _objectivepgp_PEM_read_bio_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DSAparams
%xdefine _objectivepgp_PEM_read_bio_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_ECPrivateKey
%xdefine _objectivepgp_PEM_read_bio_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_EC_PUBKEY
%xdefine _objectivepgp_PEM_read_bio_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS7
%xdefine _objectivepgp_PEM_read_bio_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PUBKEY
%xdefine _objectivepgp_PEM_read_bio_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSAPrivateKey
%xdefine _objectivepgp_PEM_read_bio_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSAPublicKey
%xdefine _objectivepgp_PEM_read_bio_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_RSA_PUBKEY
%xdefine _objectivepgp_PEM_read_bio_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_CRL
%xdefine _objectivepgp_PEM_read_bio_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_REQ
%xdefine _objectivepgp_PEM_write_DHparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DHparams
%xdefine _objectivepgp_PEM_write_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSAPrivateKey
%xdefine _objectivepgp_PEM_write_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSA_PUBKEY
%xdefine _objectivepgp_PEM_write_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_DSAparams
%xdefine _objectivepgp_PEM_write_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_ECPrivateKey
%xdefine _objectivepgp_PEM_write_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_EC_PUBKEY
%xdefine _objectivepgp_PEM_write_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS7
%xdefine _objectivepgp_PEM_write_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PUBKEY
%xdefine _objectivepgp_PEM_write_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSAPrivateKey
%xdefine _objectivepgp_PEM_write_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSAPublicKey
%xdefine _objectivepgp_PEM_write_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_RSA_PUBKEY
%xdefine _objectivepgp_PEM_write_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_CRL
%xdefine _objectivepgp_PEM_write_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_REQ
%xdefine _objectivepgp_PEM_write_X509_REQ_NEW BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_REQ_NEW
%xdefine _objectivepgp_PEM_write_bio_DHparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DHparams
%xdefine _objectivepgp_PEM_write_bio_DSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSAPrivateKey
%xdefine _objectivepgp_PEM_write_bio_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSA_PUBKEY
%xdefine _objectivepgp_PEM_write_bio_DSAparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_DSAparams
%xdefine _objectivepgp_PEM_write_bio_ECPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_ECPrivateKey
%xdefine _objectivepgp_PEM_write_bio_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_EC_PUBKEY
%xdefine _objectivepgp_PEM_write_bio_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS7
%xdefine _objectivepgp_PEM_write_bio_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PUBKEY
%xdefine _objectivepgp_PEM_write_bio_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSAPrivateKey
%xdefine _objectivepgp_PEM_write_bio_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSAPublicKey
%xdefine _objectivepgp_PEM_write_bio_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_RSA_PUBKEY
%xdefine _objectivepgp_PEM_write_bio_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_CRL
%xdefine _objectivepgp_PEM_write_bio_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_REQ
%xdefine _objectivepgp_PEM_write_bio_X509_REQ_NEW BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_REQ_NEW
%xdefine _objectivepgp_PEM_X509_INFO_read BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_read
%xdefine _objectivepgp_PEM_X509_INFO_read_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_read_bio
%xdefine _objectivepgp_PEM_X509_INFO_write_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_X509_INFO_write_bio
%xdefine _objectivepgp_PEM_ASN1_read BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_read
%xdefine _objectivepgp_PEM_ASN1_write BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_write
%xdefine _objectivepgp_PEM_ASN1_write_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_write_bio
%xdefine _objectivepgp_PEM_bytes_read_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_bytes_read_bio
%xdefine _objectivepgp_PEM_def_callback BORINGSSL_PREFIX %+ __objectivepgp_PEM_def_callback
%xdefine _objectivepgp_PEM_dek_info BORINGSSL_PREFIX %+ __objectivepgp_PEM_dek_info
%xdefine _objectivepgp_PEM_do_header BORINGSSL_PREFIX %+ __objectivepgp_PEM_do_header
%xdefine _objectivepgp_PEM_get_EVP_CIPHER_INFO BORINGSSL_PREFIX %+ __objectivepgp_PEM_get_EVP_CIPHER_INFO
%xdefine _objectivepgp_PEM_proc_type BORINGSSL_PREFIX %+ __objectivepgp_PEM_proc_type
%xdefine _objectivepgp_PEM_read BORINGSSL_PREFIX %+ __objectivepgp_PEM_read
%xdefine _objectivepgp_PEM_read_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio
%xdefine _objectivepgp_PEM_write BORINGSSL_PREFIX %+ __objectivepgp_PEM_write
%xdefine _objectivepgp_PEM_write_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio
%xdefine _objectivepgp_PEM_ASN1_read_bio BORINGSSL_PREFIX %+ __objectivepgp_PEM_ASN1_read_bio
%xdefine _objectivepgp_PEM_read_PKCS8 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS8
%xdefine _objectivepgp_PEM_read_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_PEM_read_bio_PKCS8 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS8
%xdefine _objectivepgp_PEM_read_bio_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_PEM_write_PKCS8 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8
%xdefine _objectivepgp_PEM_write_PKCS8PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8PrivateKey
%xdefine _objectivepgp_PEM_write_PKCS8PrivateKey_nid BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8PrivateKey_nid
%xdefine _objectivepgp_PEM_write_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_PEM_write_bio_PKCS8 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8
%xdefine _objectivepgp_PEM_write_bio_PKCS8PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8PrivateKey
%xdefine _objectivepgp_PEM_write_bio_PKCS8PrivateKey_nid BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8PrivateKey_nid
%xdefine _objectivepgp_PEM_write_bio_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_d2i_PKCS8PrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8PrivateKey_bio
%xdefine _objectivepgp_d2i_PKCS8PrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8PrivateKey_fp
%xdefine _objectivepgp_i2d_PKCS8PrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_bio
%xdefine _objectivepgp_i2d_PKCS8PrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_fp
%xdefine _objectivepgp_i2d_PKCS8PrivateKey_nid_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_nid_bio
%xdefine _objectivepgp_i2d_PKCS8PrivateKey_nid_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKey_nid_fp
%xdefine _objectivepgp_PEM_read_DHparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_DHparams
%xdefine _objectivepgp_PEM_read_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_PrivateKey
%xdefine _objectivepgp_PEM_read_bio_DHparams BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_DHparams
%xdefine _objectivepgp_PEM_read_bio_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_PrivateKey
%xdefine _objectivepgp_PEM_write_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_PrivateKey
%xdefine _objectivepgp_PEM_write_bio_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_PrivateKey
%xdefine _objectivepgp_PEM_read_X509 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509
%xdefine _objectivepgp_PEM_read_bio_X509 BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509
%xdefine _objectivepgp_PEM_write_X509 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509
%xdefine _objectivepgp_PEM_write_bio_X509 BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509
%xdefine _objectivepgp_PEM_read_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_X509_AUX
%xdefine _objectivepgp_PEM_read_bio_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_PEM_read_bio_X509_AUX
%xdefine _objectivepgp_PEM_write_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_X509_AUX
%xdefine _objectivepgp_PEM_write_bio_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_PEM_write_bio_X509_AUX
%xdefine _objectivepgp_PKCS7_get_raw_certificates BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_raw_certificates
%xdefine _objectivepgp_pkcs7_bundle BORINGSSL_PREFIX %+ __objectivepgp_pkcs7_bundle
%xdefine _objectivepgp_pkcs7_parse_header BORINGSSL_PREFIX %+ __objectivepgp_pkcs7_parse_header
%xdefine _objectivepgp_PKCS7_bundle_CRLs BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_bundle_CRLs
%xdefine _objectivepgp_PKCS7_bundle_certificates BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_bundle_certificates
%xdefine _objectivepgp_PKCS7_free BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_free
%xdefine _objectivepgp_PKCS7_get_CRLs BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_CRLs
%xdefine _objectivepgp_PKCS7_get_PEM_CRLs BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_PEM_CRLs
%xdefine _objectivepgp_PKCS7_get_PEM_certificates BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_PEM_certificates
%xdefine _objectivepgp_PKCS7_get_certificates BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_get_certificates
%xdefine _objectivepgp_PKCS7_sign BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_sign
%xdefine _objectivepgp_PKCS7_type_is_data BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_data
%xdefine _objectivepgp_PKCS7_type_is_digest BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_digest
%xdefine _objectivepgp_PKCS7_type_is_encrypted BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_encrypted
%xdefine _objectivepgp_PKCS7_type_is_enveloped BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_enveloped
%xdefine _objectivepgp_PKCS7_type_is_signed BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_signed
%xdefine _objectivepgp_PKCS7_type_is_signedAndEnveloped BORINGSSL_PREFIX %+ __objectivepgp_PKCS7_type_is_signedAndEnveloped
%xdefine _objectivepgp_d2i_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS7
%xdefine _objectivepgp_d2i_PKCS7_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS7_bio
%xdefine _objectivepgp_i2d_PKCS7 BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS7
%xdefine _objectivepgp_i2d_PKCS7_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS7_bio
%xdefine _objectivepgp_PKCS8_marshal_encrypted_private_key BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_marshal_encrypted_private_key
%xdefine _objectivepgp_PKCS8_parse_encrypted_private_key BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_parse_encrypted_private_key
%xdefine _objectivepgp_pkcs12_key_gen BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_key_gen
%xdefine _objectivepgp_pkcs12_pbe_encrypt_init BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_pbe_encrypt_init
%xdefine _objectivepgp_pkcs8_pbe_decrypt BORINGSSL_PREFIX %+ __objectivepgp_pkcs8_pbe_decrypt
%xdefine _objectivepgp_EVP_PKCS82PKEY BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKCS82PKEY
%xdefine _objectivepgp_EVP_PKEY2PKCS8 BORINGSSL_PREFIX %+ __objectivepgp_EVP_PKEY2PKCS8
%xdefine _objectivepgp_PKCS12_PBE_add BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_PBE_add
%xdefine _objectivepgp_PKCS12_create BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_create
%xdefine _objectivepgp_PKCS12_free BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_free
%xdefine _objectivepgp_PKCS12_get_key_and_certs BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_get_key_and_certs
%xdefine _objectivepgp_PKCS12_parse BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_parse
%xdefine _objectivepgp_PKCS12_verify_mac BORINGSSL_PREFIX %+ __objectivepgp_PKCS12_verify_mac
%xdefine _objectivepgp_PKCS8_PRIV_KEY_INFO_free BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_free
%xdefine _objectivepgp_PKCS8_PRIV_KEY_INFO_it BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_it
%xdefine _objectivepgp_PKCS8_PRIV_KEY_INFO_new BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_PRIV_KEY_INFO_new
%xdefine _objectivepgp_PKCS8_decrypt BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_decrypt
%xdefine _objectivepgp_PKCS8_encrypt BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_encrypt
%xdefine _objectivepgp_d2i_PKCS12 BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12
%xdefine _objectivepgp_d2i_PKCS12_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12_bio
%xdefine _objectivepgp_d2i_PKCS12_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS12_fp
%xdefine _objectivepgp_d2i_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_i2d_PKCS12 BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12
%xdefine _objectivepgp_i2d_PKCS12_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12_bio
%xdefine _objectivepgp_i2d_PKCS12_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS12_fp
%xdefine _objectivepgp_i2d_PKCS8_PRIV_KEY_INFO BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO
%xdefine _objectivepgp_pkcs12_iterations_acceptable BORINGSSL_PREFIX %+ __objectivepgp_pkcs12_iterations_acceptable
%xdefine _objectivepgp_PKCS5_pbe2_decrypt_init BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_pbe2_decrypt_init
%xdefine _objectivepgp_PKCS5_pbe2_encrypt_init BORINGSSL_PREFIX %+ __objectivepgp_PKCS5_pbe2_encrypt_init
%xdefine _objectivepgp_CRYPTO_poly1305_finish BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_finish
%xdefine _objectivepgp_CRYPTO_poly1305_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_init
%xdefine _objectivepgp_CRYPTO_poly1305_update BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_poly1305_update
%xdefine _objectivepgp_CRYPTO_BUFFER_POOL_free BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_POOL_free
%xdefine _objectivepgp_CRYPTO_BUFFER_POOL_new BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_POOL_new
%xdefine _objectivepgp_CRYPTO_BUFFER_alloc BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_alloc
%xdefine _objectivepgp_CRYPTO_BUFFER_data BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_data
%xdefine _objectivepgp_CRYPTO_BUFFER_free BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_free
%xdefine _objectivepgp_CRYPTO_BUFFER_init_CBS BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_init_CBS
%xdefine _objectivepgp_CRYPTO_BUFFER_len BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_len
%xdefine _objectivepgp_CRYPTO_BUFFER_new BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_new
%xdefine _objectivepgp_CRYPTO_BUFFER_new_from_CBS BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_new_from_CBS
%xdefine _objectivepgp_CRYPTO_BUFFER_up_ref BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_BUFFER_up_ref
%xdefine _objectivepgp_RAND_enable_fork_unsafe_buffering BORINGSSL_PREFIX %+ __objectivepgp_RAND_enable_fork_unsafe_buffering
%xdefine _objectivepgp_rand_fork_unsafe_buffering_enabled BORINGSSL_PREFIX %+ __objectivepgp_rand_fork_unsafe_buffering_enabled
%xdefine _objectivepgp_RAND_SSLeay BORINGSSL_PREFIX %+ __objectivepgp_RAND_SSLeay
%xdefine _objectivepgp_RAND_add BORINGSSL_PREFIX %+ __objectivepgp_RAND_add
%xdefine _objectivepgp_RAND_cleanup BORINGSSL_PREFIX %+ __objectivepgp_RAND_cleanup
%xdefine _objectivepgp_RAND_egd BORINGSSL_PREFIX %+ __objectivepgp_RAND_egd
%xdefine _objectivepgp_RAND_file_name BORINGSSL_PREFIX %+ __objectivepgp_RAND_file_name
%xdefine _objectivepgp_RAND_get_rand_method BORINGSSL_PREFIX %+ __objectivepgp_RAND_get_rand_method
%xdefine _objectivepgp_RAND_load_file BORINGSSL_PREFIX %+ __objectivepgp_RAND_load_file
%xdefine _objectivepgp_RAND_poll BORINGSSL_PREFIX %+ __objectivepgp_RAND_poll
%xdefine _objectivepgp_RAND_seed BORINGSSL_PREFIX %+ __objectivepgp_RAND_seed
%xdefine _objectivepgp_RAND_set_rand_method BORINGSSL_PREFIX %+ __objectivepgp_RAND_set_rand_method
%xdefine _objectivepgp_RAND_status BORINGSSL_PREFIX %+ __objectivepgp_RAND_status
%xdefine _objectivepgp_RC4 BORINGSSL_PREFIX %+ __objectivepgp_RC4
%xdefine _objectivepgp_RC4_set_key BORINGSSL_PREFIX %+ __objectivepgp_RC4_set_key
%xdefine _objectivepgp_CRYPTO_refcount_dec_and_test_zero BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_refcount_dec_and_test_zero
%xdefine _objectivepgp_CRYPTO_refcount_inc BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_refcount_inc
%xdefine _objectivepgp_RSAPrivateKey_dup BORINGSSL_PREFIX %+ __objectivepgp_RSAPrivateKey_dup
%xdefine _objectivepgp_RSAPublicKey_dup BORINGSSL_PREFIX %+ __objectivepgp_RSAPublicKey_dup
%xdefine _objectivepgp_RSA_marshal_private_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_marshal_private_key
%xdefine _objectivepgp_RSA_marshal_public_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_marshal_public_key
%xdefine _objectivepgp_RSA_parse_private_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_parse_private_key
%xdefine _objectivepgp_RSA_parse_public_key BORINGSSL_PREFIX %+ __objectivepgp_RSA_parse_public_key
%xdefine _objectivepgp_RSA_private_key_from_bytes BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_key_from_bytes
%xdefine _objectivepgp_RSA_private_key_to_bytes BORINGSSL_PREFIX %+ __objectivepgp_RSA_private_key_to_bytes
%xdefine _objectivepgp_RSA_public_key_from_bytes BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_key_from_bytes
%xdefine _objectivepgp_RSA_public_key_to_bytes BORINGSSL_PREFIX %+ __objectivepgp_RSA_public_key_to_bytes
%xdefine _objectivepgp_d2i_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey
%xdefine _objectivepgp_d2i_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey
%xdefine _objectivepgp_i2d_RSAPrivateKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey
%xdefine _objectivepgp_i2d_RSAPublicKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey
%xdefine _objectivepgp_RSA_print BORINGSSL_PREFIX %+ __objectivepgp_RSA_print
%xdefine _objectivepgp_sk_deep_copy BORINGSSL_PREFIX %+ __objectivepgp_sk_deep_copy
%xdefine _objectivepgp_sk_delete BORINGSSL_PREFIX %+ __objectivepgp_sk_delete
%xdefine _objectivepgp_sk_delete_ptr BORINGSSL_PREFIX %+ __objectivepgp_sk_delete_ptr
%xdefine _objectivepgp_sk_dup BORINGSSL_PREFIX %+ __objectivepgp_sk_dup
%xdefine _objectivepgp_sk_find BORINGSSL_PREFIX %+ __objectivepgp_sk_find
%xdefine _objectivepgp_sk_free BORINGSSL_PREFIX %+ __objectivepgp_sk_free
%xdefine _objectivepgp_sk_insert BORINGSSL_PREFIX %+ __objectivepgp_sk_insert
%xdefine _objectivepgp_sk_is_sorted BORINGSSL_PREFIX %+ __objectivepgp_sk_is_sorted
%xdefine _objectivepgp_sk_new BORINGSSL_PREFIX %+ __objectivepgp_sk_new
%xdefine _objectivepgp_sk_new_null BORINGSSL_PREFIX %+ __objectivepgp_sk_new_null
%xdefine _objectivepgp_sk_num BORINGSSL_PREFIX %+ __objectivepgp_sk_num
%xdefine _objectivepgp_sk_pop BORINGSSL_PREFIX %+ __objectivepgp_sk_pop
%xdefine _objectivepgp_sk_pop_free BORINGSSL_PREFIX %+ __objectivepgp_sk_pop_free
%xdefine _objectivepgp_sk_pop_free_ex BORINGSSL_PREFIX %+ __objectivepgp_sk_pop_free_ex
%xdefine _objectivepgp_sk_push BORINGSSL_PREFIX %+ __objectivepgp_sk_push
%xdefine _objectivepgp_sk_set BORINGSSL_PREFIX %+ __objectivepgp_sk_set
%xdefine _objectivepgp_sk_set_cmp_func BORINGSSL_PREFIX %+ __objectivepgp_sk_set_cmp_func
%xdefine _objectivepgp_sk_shift BORINGSSL_PREFIX %+ __objectivepgp_sk_shift
%xdefine _objectivepgp_sk_sort BORINGSSL_PREFIX %+ __objectivepgp_sk_sort
%xdefine _objectivepgp_sk_value BORINGSSL_PREFIX %+ __objectivepgp_sk_value
%xdefine _objectivepgp_sk_zero BORINGSSL_PREFIX %+ __objectivepgp_sk_zero
%xdefine _objectivepgp_SIPHASH_24 BORINGSSL_PREFIX %+ __objectivepgp_SIPHASH_24
%xdefine _objectivepgp_CRYPTO_THREADID_current BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_current
%xdefine _objectivepgp_CRYPTO_THREADID_set_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_callback
%xdefine _objectivepgp_CRYPTO_THREADID_set_numeric BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_numeric
%xdefine _objectivepgp_CRYPTO_THREADID_set_pointer BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_THREADID_set_pointer
%xdefine _objectivepgp_CRYPTO_get_dynlock_create_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_create_callback
%xdefine _objectivepgp_CRYPTO_get_dynlock_destroy_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_destroy_callback
%xdefine _objectivepgp_CRYPTO_get_dynlock_lock_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_dynlock_lock_callback
%xdefine _objectivepgp_CRYPTO_get_lock_name BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_lock_name
%xdefine _objectivepgp_CRYPTO_get_locking_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_locking_callback
%xdefine _objectivepgp_CRYPTO_num_locks BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_num_locks
%xdefine _objectivepgp_CRYPTO_set_add_lock_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_add_lock_callback
%xdefine _objectivepgp_CRYPTO_set_dynlock_create_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_create_callback
%xdefine _objectivepgp_CRYPTO_set_dynlock_destroy_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_destroy_callback
%xdefine _objectivepgp_CRYPTO_set_dynlock_lock_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_dynlock_lock_callback
%xdefine _objectivepgp_CRYPTO_set_id_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_id_callback
%xdefine _objectivepgp_CRYPTO_set_locking_callback BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_locking_callback
%xdefine _objectivepgp_CRYPTO_MUTEX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_cleanup
%xdefine _objectivepgp_CRYPTO_MUTEX_init BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_init
%xdefine _objectivepgp_CRYPTO_MUTEX_lock_read BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_lock_read
%xdefine _objectivepgp_CRYPTO_MUTEX_lock_write BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_lock_write
%xdefine _objectivepgp_CRYPTO_MUTEX_unlock_read BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_unlock_read
%xdefine _objectivepgp_CRYPTO_MUTEX_unlock_write BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_MUTEX_unlock_write
%xdefine _objectivepgp_CRYPTO_STATIC_MUTEX_lock_read BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_lock_read
%xdefine _objectivepgp_CRYPTO_STATIC_MUTEX_lock_write BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_lock_write
%xdefine _objectivepgp_CRYPTO_STATIC_MUTEX_unlock_read BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_read
%xdefine _objectivepgp_CRYPTO_STATIC_MUTEX_unlock_write BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_STATIC_MUTEX_unlock_write
%xdefine _objectivepgp_CRYPTO_get_thread_local BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_get_thread_local
%xdefine _objectivepgp_CRYPTO_once BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_once
%xdefine _objectivepgp_CRYPTO_set_thread_local BORINGSSL_PREFIX %+ __objectivepgp_CRYPTO_set_thread_local
%xdefine _objectivepgp_ASN1_digest BORINGSSL_PREFIX %+ __objectivepgp_ASN1_digest
%xdefine _objectivepgp_ASN1_item_digest BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_digest
%xdefine _objectivepgp_ASN1_item_sign BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_sign
%xdefine _objectivepgp_ASN1_item_sign_ctx BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_sign_ctx
%xdefine _objectivepgp_ASN1_STRING_print_ex BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print_ex
%xdefine _objectivepgp_ASN1_STRING_print_ex_fp BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print_ex_fp
%xdefine _objectivepgp_ASN1_STRING_to_UTF8 BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_to_UTF8
%xdefine _objectivepgp_X509_NAME_print_ex BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print_ex
%xdefine _objectivepgp_X509_NAME_print_ex_fp BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print_ex_fp
%xdefine _objectivepgp_ASN1_item_verify BORINGSSL_PREFIX %+ __objectivepgp_ASN1_item_verify
%xdefine _objectivepgp_x509_digest_sign_algorithm BORINGSSL_PREFIX %+ __objectivepgp_x509_digest_sign_algorithm
%xdefine _objectivepgp_x509_digest_verify_init BORINGSSL_PREFIX %+ __objectivepgp_x509_digest_verify_init
%xdefine _objectivepgp_ASN1_generate_nconf BORINGSSL_PREFIX %+ __objectivepgp_ASN1_generate_nconf
%xdefine _objectivepgp_ASN1_generate_v3 BORINGSSL_PREFIX %+ __objectivepgp_ASN1_generate_v3
%xdefine _objectivepgp_X509_LOOKUP_hash_dir BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_hash_dir
%xdefine _objectivepgp_X509_LOOKUP_file BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_file
%xdefine _objectivepgp_X509_load_cert_crl_file BORINGSSL_PREFIX %+ __objectivepgp_X509_load_cert_crl_file
%xdefine _objectivepgp_X509_load_cert_file BORINGSSL_PREFIX %+ __objectivepgp_X509_load_cert_file
%xdefine _objectivepgp_X509_load_crl_file BORINGSSL_PREFIX %+ __objectivepgp_X509_load_crl_file
%xdefine _objectivepgp_i2d_PrivateKey BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey
%xdefine _objectivepgp_RSA_PSS_PARAMS_free BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_free
%xdefine _objectivepgp_RSA_PSS_PARAMS_it BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_it
%xdefine _objectivepgp_RSA_PSS_PARAMS_new BORINGSSL_PREFIX %+ __objectivepgp_RSA_PSS_PARAMS_new
%xdefine _objectivepgp_d2i_RSA_PSS_PARAMS BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PSS_PARAMS
%xdefine _objectivepgp_i2d_RSA_PSS_PARAMS BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PSS_PARAMS
%xdefine _objectivepgp_x509_print_rsa_pss_params BORINGSSL_PREFIX %+ __objectivepgp_x509_print_rsa_pss_params
%xdefine _objectivepgp_x509_rsa_ctx_to_pss BORINGSSL_PREFIX %+ __objectivepgp_x509_rsa_ctx_to_pss
%xdefine _objectivepgp_x509_rsa_pss_to_ctx BORINGSSL_PREFIX %+ __objectivepgp_x509_rsa_pss_to_ctx
%xdefine _objectivepgp_X509_CRL_print BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_print
%xdefine _objectivepgp_X509_CRL_print_fp BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_print_fp
%xdefine _objectivepgp_X509_REQ_print BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print
%xdefine _objectivepgp_X509_REQ_print_ex BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print_ex
%xdefine _objectivepgp_X509_REQ_print_fp BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_print_fp
%xdefine _objectivepgp_ASN1_GENERALIZEDTIME_print BORINGSSL_PREFIX %+ __objectivepgp_ASN1_GENERALIZEDTIME_print
%xdefine _objectivepgp_ASN1_STRING_print BORINGSSL_PREFIX %+ __objectivepgp_ASN1_STRING_print
%xdefine _objectivepgp_ASN1_TIME_print BORINGSSL_PREFIX %+ __objectivepgp_ASN1_TIME_print
%xdefine _objectivepgp_ASN1_UTCTIME_print BORINGSSL_PREFIX %+ __objectivepgp_ASN1_UTCTIME_print
%xdefine _objectivepgp_X509_NAME_print BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_print
%xdefine _objectivepgp_X509_ocspid_print BORINGSSL_PREFIX %+ __objectivepgp_X509_ocspid_print
%xdefine _objectivepgp_X509_print BORINGSSL_PREFIX %+ __objectivepgp_X509_print
%xdefine _objectivepgp_X509_print_ex BORINGSSL_PREFIX %+ __objectivepgp_X509_print_ex
%xdefine _objectivepgp_X509_print_ex_fp BORINGSSL_PREFIX %+ __objectivepgp_X509_print_ex_fp
%xdefine _objectivepgp_X509_print_fp BORINGSSL_PREFIX %+ __objectivepgp_X509_print_fp
%xdefine _objectivepgp_X509_signature_print BORINGSSL_PREFIX %+ __objectivepgp_X509_signature_print
%xdefine _objectivepgp_X509_CERT_AUX_print BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_print
%xdefine _objectivepgp_PKCS8_pkey_get0 BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_pkey_get0
%xdefine _objectivepgp_PKCS8_pkey_set0 BORINGSSL_PREFIX %+ __objectivepgp_PKCS8_pkey_set0
%xdefine _objectivepgp_X509_signature_dump BORINGSSL_PREFIX %+ __objectivepgp_X509_signature_dump
%xdefine _objectivepgp_X509_ATTRIBUTE_count BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_count
%xdefine _objectivepgp_X509_ATTRIBUTE_create_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_NID
%xdefine _objectivepgp_X509_ATTRIBUTE_create_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_OBJ
%xdefine _objectivepgp_X509_ATTRIBUTE_create_by_txt BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create_by_txt
%xdefine _objectivepgp_X509_ATTRIBUTE_get0_data BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_data
%xdefine _objectivepgp_X509_ATTRIBUTE_get0_object BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_object
%xdefine _objectivepgp_X509_ATTRIBUTE_get0_type BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_get0_type
%xdefine _objectivepgp_X509_ATTRIBUTE_set1_data BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_set1_data
%xdefine _objectivepgp_X509_ATTRIBUTE_set1_object BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_set1_object
%xdefine _objectivepgp_X509at_add1_attr BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr
%xdefine _objectivepgp_X509at_add1_attr_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_NID
%xdefine _objectivepgp_X509at_add1_attr_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_OBJ
%xdefine _objectivepgp_X509at_add1_attr_by_txt BORINGSSL_PREFIX %+ __objectivepgp_X509at_add1_attr_by_txt
%xdefine _objectivepgp_X509at_delete_attr BORINGSSL_PREFIX %+ __objectivepgp_X509at_delete_attr
%xdefine _objectivepgp_X509at_get0_data_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get0_data_by_OBJ
%xdefine _objectivepgp_X509at_get_attr BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr
%xdefine _objectivepgp_X509at_get_attr_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_by_NID
%xdefine _objectivepgp_X509at_get_attr_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_by_OBJ
%xdefine _objectivepgp_X509at_get_attr_count BORINGSSL_PREFIX %+ __objectivepgp_X509at_get_attr_count
%xdefine _objectivepgp_X509_CRL_check_suiteb BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_check_suiteb
%xdefine _objectivepgp_X509_CRL_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_cmp
%xdefine _objectivepgp_X509_CRL_match BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_match
%xdefine _objectivepgp_X509_NAME_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_cmp
%xdefine _objectivepgp_X509_NAME_hash BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_hash
%xdefine _objectivepgp_X509_NAME_hash_old BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_hash_old
%xdefine _objectivepgp_X509_chain_check_suiteb BORINGSSL_PREFIX %+ __objectivepgp_X509_chain_check_suiteb
%xdefine _objectivepgp_X509_chain_up_ref BORINGSSL_PREFIX %+ __objectivepgp_X509_chain_up_ref
%xdefine _objectivepgp_X509_check_private_key BORINGSSL_PREFIX %+ __objectivepgp_X509_check_private_key
%xdefine _objectivepgp_X509_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp
%xdefine _objectivepgp_X509_find_by_issuer_and_serial BORINGSSL_PREFIX %+ __objectivepgp_X509_find_by_issuer_and_serial
%xdefine _objectivepgp_X509_find_by_subject BORINGSSL_PREFIX %+ __objectivepgp_X509_find_by_subject
%xdefine _objectivepgp_X509_get0_pubkey_bitstr BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_pubkey_bitstr
%xdefine _objectivepgp_X509_get_issuer_name BORINGSSL_PREFIX %+ __objectivepgp_X509_get_issuer_name
%xdefine _objectivepgp_X509_get_pubkey BORINGSSL_PREFIX %+ __objectivepgp_X509_get_pubkey
%xdefine _objectivepgp_X509_get_serialNumber BORINGSSL_PREFIX %+ __objectivepgp_X509_get_serialNumber
%xdefine _objectivepgp_X509_get_subject_name BORINGSSL_PREFIX %+ __objectivepgp_X509_get_subject_name
%xdefine _objectivepgp_X509_issuer_and_serial_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_and_serial_cmp
%xdefine _objectivepgp_X509_issuer_and_serial_hash BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_and_serial_hash
%xdefine _objectivepgp_X509_issuer_name_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_cmp
%xdefine _objectivepgp_X509_issuer_name_hash BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_hash
%xdefine _objectivepgp_X509_issuer_name_hash_old BORINGSSL_PREFIX %+ __objectivepgp_X509_issuer_name_hash_old
%xdefine _objectivepgp_X509_subject_name_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_cmp
%xdefine _objectivepgp_X509_subject_name_hash BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_hash
%xdefine _objectivepgp_X509_subject_name_hash_old BORINGSSL_PREFIX %+ __objectivepgp_X509_subject_name_hash_old
%xdefine _objectivepgp_X509_STORE_load_locations BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_load_locations
%xdefine _objectivepgp_X509_STORE_set_default_paths BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_default_paths
%xdefine _objectivepgp_X509_get_default_cert_area BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_area
%xdefine _objectivepgp_X509_get_default_cert_dir BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_dir
%xdefine _objectivepgp_X509_get_default_cert_dir_env BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_dir_env
%xdefine _objectivepgp_X509_get_default_cert_file BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_file
%xdefine _objectivepgp_X509_get_default_cert_file_env BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_cert_file_env
%xdefine _objectivepgp_X509_get_default_private_dir BORINGSSL_PREFIX %+ __objectivepgp_X509_get_default_private_dir
%xdefine _objectivepgp_X509_CRL_add1_ext_i2d BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add1_ext_i2d
%xdefine _objectivepgp_X509_CRL_add_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add_ext
%xdefine _objectivepgp_X509_CRL_delete_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_delete_ext
%xdefine _objectivepgp_X509_CRL_get_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext
%xdefine _objectivepgp_X509_CRL_get_ext_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_NID
%xdefine _objectivepgp_X509_CRL_get_ext_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_OBJ
%xdefine _objectivepgp_X509_CRL_get_ext_by_critical BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_by_critical
%xdefine _objectivepgp_X509_CRL_get_ext_count BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_count
%xdefine _objectivepgp_X509_CRL_get_ext_d2i BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_ext_d2i
%xdefine _objectivepgp_X509_REVOKED_add1_ext_i2d BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_add1_ext_i2d
%xdefine _objectivepgp_X509_REVOKED_add_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_add_ext
%xdefine _objectivepgp_X509_REVOKED_delete_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_delete_ext
%xdefine _objectivepgp_X509_REVOKED_get_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext
%xdefine _objectivepgp_X509_REVOKED_get_ext_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_NID
%xdefine _objectivepgp_X509_REVOKED_get_ext_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_OBJ
%xdefine _objectivepgp_X509_REVOKED_get_ext_by_critical BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_by_critical
%xdefine _objectivepgp_X509_REVOKED_get_ext_count BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_count
%xdefine _objectivepgp_X509_REVOKED_get_ext_d2i BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get_ext_d2i
%xdefine _objectivepgp_X509_add1_ext_i2d BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_ext_i2d
%xdefine _objectivepgp_X509_add_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_add_ext
%xdefine _objectivepgp_X509_delete_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_delete_ext
%xdefine _objectivepgp_X509_get_ext BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext
%xdefine _objectivepgp_X509_get_ext_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_NID
%xdefine _objectivepgp_X509_get_ext_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_OBJ
%xdefine _objectivepgp_X509_get_ext_by_critical BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_by_critical
%xdefine _objectivepgp_X509_get_ext_count BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_count
%xdefine _objectivepgp_X509_get_ext_d2i BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ext_d2i
%xdefine _objectivepgp_X509_LOOKUP_by_alias BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_alias
%xdefine _objectivepgp_X509_LOOKUP_by_fingerprint BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_fingerprint
%xdefine _objectivepgp_X509_LOOKUP_by_issuer_serial BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_issuer_serial
%xdefine _objectivepgp_X509_LOOKUP_by_subject BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_by_subject
%xdefine _objectivepgp_X509_LOOKUP_ctrl BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_ctrl
%xdefine _objectivepgp_X509_LOOKUP_free BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_free
%xdefine _objectivepgp_X509_LOOKUP_init BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_init
%xdefine _objectivepgp_X509_LOOKUP_new BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_new
%xdefine _objectivepgp_X509_LOOKUP_shutdown BORINGSSL_PREFIX %+ __objectivepgp_X509_LOOKUP_shutdown
%xdefine _objectivepgp_X509_OBJECT_free_contents BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_free_contents
%xdefine _objectivepgp_X509_OBJECT_get0_X509 BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_get0_X509
%xdefine _objectivepgp_X509_OBJECT_get_type BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_get_type
%xdefine _objectivepgp_X509_OBJECT_idx_by_subject BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_idx_by_subject
%xdefine _objectivepgp_X509_OBJECT_retrieve_by_subject BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_retrieve_by_subject
%xdefine _objectivepgp_X509_OBJECT_retrieve_match BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_retrieve_match
%xdefine _objectivepgp_X509_OBJECT_up_ref_count BORINGSSL_PREFIX %+ __objectivepgp_X509_OBJECT_up_ref_count
%xdefine _objectivepgp_X509_STORE_CTX_get0_store BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_store
%xdefine _objectivepgp_X509_STORE_CTX_get1_issuer BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get1_issuer
%xdefine _objectivepgp_X509_STORE_add_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_cert
%xdefine _objectivepgp_X509_STORE_add_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_crl
%xdefine _objectivepgp_X509_STORE_add_lookup BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_add_lookup
%xdefine _objectivepgp_X509_STORE_free BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_free
%xdefine _objectivepgp_X509_STORE_get0_objects BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get0_objects
%xdefine _objectivepgp_X509_STORE_get0_param BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get0_param
%xdefine _objectivepgp_X509_STORE_get1_certs BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get1_certs
%xdefine _objectivepgp_X509_STORE_get1_crls BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get1_crls
%xdefine _objectivepgp_X509_STORE_get_by_subject BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_by_subject
%xdefine _objectivepgp_X509_STORE_get_cert_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_cert_crl
%xdefine _objectivepgp_X509_STORE_get_check_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_crl
%xdefine _objectivepgp_X509_STORE_get_check_issued BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_issued
%xdefine _objectivepgp_X509_STORE_get_check_revocation BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_check_revocation
%xdefine _objectivepgp_X509_STORE_get_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_cleanup
%xdefine _objectivepgp_X509_STORE_get_get_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_get_crl
%xdefine _objectivepgp_X509_STORE_get_get_issuer BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_get_issuer
%xdefine _objectivepgp_X509_STORE_get_lookup_certs BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_lookup_certs
%xdefine _objectivepgp_X509_STORE_get_lookup_crls BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_lookup_crls
%xdefine _objectivepgp_X509_STORE_get_verify BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_verify
%xdefine _objectivepgp_X509_STORE_get_verify_cb BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_get_verify_cb
%xdefine _objectivepgp_X509_STORE_new BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_new
%xdefine _objectivepgp_X509_STORE_set0_additional_untrusted BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set0_additional_untrusted
%xdefine _objectivepgp_X509_STORE_set1_param BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set1_param
%xdefine _objectivepgp_X509_STORE_set_cert_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_cert_crl
%xdefine _objectivepgp_X509_STORE_set_check_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_crl
%xdefine _objectivepgp_X509_STORE_set_check_issued BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_issued
%xdefine _objectivepgp_X509_STORE_set_check_revocation BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_check_revocation
%xdefine _objectivepgp_X509_STORE_set_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_cleanup
%xdefine _objectivepgp_X509_STORE_set_depth BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_depth
%xdefine _objectivepgp_X509_STORE_set_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_flags
%xdefine _objectivepgp_X509_STORE_set_get_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_get_crl
%xdefine _objectivepgp_X509_STORE_set_get_issuer BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_get_issuer
%xdefine _objectivepgp_X509_STORE_set_lookup_certs BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_lookup_certs
%xdefine _objectivepgp_X509_STORE_set_lookup_crls BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_lookup_crls
%xdefine _objectivepgp_X509_STORE_set_purpose BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_purpose
%xdefine _objectivepgp_X509_STORE_set_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_trust
%xdefine _objectivepgp_X509_STORE_set_verify BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_verify
%xdefine _objectivepgp_X509_STORE_set_verify_cb BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_set_verify_cb
%xdefine _objectivepgp_X509_STORE_up_ref BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_up_ref
%xdefine _objectivepgp_X509_NAME_oneline BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_oneline
%xdefine _objectivepgp_X509_REQ_to_X509 BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_to_X509
%xdefine _objectivepgp_X509_REQ_add1_attr BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr
%xdefine _objectivepgp_X509_REQ_add1_attr_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_NID
%xdefine _objectivepgp_X509_REQ_add1_attr_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_OBJ
%xdefine _objectivepgp_X509_REQ_add1_attr_by_txt BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add1_attr_by_txt
%xdefine _objectivepgp_X509_REQ_add_extensions BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add_extensions
%xdefine _objectivepgp_X509_REQ_add_extensions_nid BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_add_extensions_nid
%xdefine _objectivepgp_X509_REQ_check_private_key BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_check_private_key
%xdefine _objectivepgp_X509_REQ_delete_attr BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_delete_attr
%xdefine _objectivepgp_X509_REQ_extension_nid BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_extension_nid
%xdefine _objectivepgp_X509_REQ_get0_signature BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get0_signature
%xdefine _objectivepgp_X509_REQ_get_attr BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr
%xdefine _objectivepgp_X509_REQ_get_attr_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_by_NID
%xdefine _objectivepgp_X509_REQ_get_attr_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_by_OBJ
%xdefine _objectivepgp_X509_REQ_get_attr_count BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_attr_count
%xdefine _objectivepgp_X509_REQ_get_extension_nids BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_extension_nids
%xdefine _objectivepgp_X509_REQ_get_extensions BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_extensions
%xdefine _objectivepgp_X509_REQ_get_pubkey BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_pubkey
%xdefine _objectivepgp_X509_REQ_get_signature_nid BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get_signature_nid
%xdefine _objectivepgp_X509_REQ_set_extension_nids BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_extension_nids
%xdefine _objectivepgp_X509_to_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_X509_to_X509_REQ
%xdefine _objectivepgp_i2d_re_X509_REQ_tbs BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_REQ_tbs
%xdefine _objectivepgp_X509_get0_extensions BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_extensions
%xdefine _objectivepgp_X509_get0_notAfter BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_notAfter
%xdefine _objectivepgp_X509_get0_notBefore BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_notBefore
%xdefine _objectivepgp_X509_get0_tbs_sigalg BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_tbs_sigalg
%xdefine _objectivepgp_X509_set_issuer_name BORINGSSL_PREFIX %+ __objectivepgp_X509_set_issuer_name
%xdefine _objectivepgp_X509_set_notAfter BORINGSSL_PREFIX %+ __objectivepgp_X509_set_notAfter
%xdefine _objectivepgp_X509_set_notBefore BORINGSSL_PREFIX %+ __objectivepgp_X509_set_notBefore
%xdefine _objectivepgp_X509_set_pubkey BORINGSSL_PREFIX %+ __objectivepgp_X509_set_pubkey
%xdefine _objectivepgp_X509_set_serialNumber BORINGSSL_PREFIX %+ __objectivepgp_X509_set_serialNumber
%xdefine _objectivepgp_X509_set_subject_name BORINGSSL_PREFIX %+ __objectivepgp_X509_set_subject_name
%xdefine _objectivepgp_X509_set_version BORINGSSL_PREFIX %+ __objectivepgp_X509_set_version
%xdefine _objectivepgp_X509_TRUST_add BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_add
%xdefine _objectivepgp_X509_TRUST_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_cleanup
%xdefine _objectivepgp_X509_TRUST_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get0
%xdefine _objectivepgp_X509_TRUST_get0_name BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get0_name
%xdefine _objectivepgp_X509_TRUST_get_by_id BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_by_id
%xdefine _objectivepgp_X509_TRUST_get_count BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_count
%xdefine _objectivepgp_X509_TRUST_get_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_flags
%xdefine _objectivepgp_X509_TRUST_get_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_get_trust
%xdefine _objectivepgp_X509_TRUST_set BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_set
%xdefine _objectivepgp_X509_TRUST_set_default BORINGSSL_PREFIX %+ __objectivepgp_X509_TRUST_set_default
%xdefine _objectivepgp_X509_check_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_check_trust
%xdefine _objectivepgp_X509_verify_cert_error_string BORINGSSL_PREFIX %+ __objectivepgp_X509_verify_cert_error_string
%xdefine _objectivepgp_X509_EXTENSION_create_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_create_by_NID
%xdefine _objectivepgp_X509_EXTENSION_create_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_create_by_OBJ
%xdefine _objectivepgp_X509_EXTENSION_get_critical BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_critical
%xdefine _objectivepgp_X509_EXTENSION_get_data BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_data
%xdefine _objectivepgp_X509_EXTENSION_get_object BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_get_object
%xdefine _objectivepgp_X509_EXTENSION_set_critical BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_critical
%xdefine _objectivepgp_X509_EXTENSION_set_data BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_data
%xdefine _objectivepgp_X509_EXTENSION_set_object BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_set_object
%xdefine _objectivepgp_X509v3_add_ext BORINGSSL_PREFIX %+ __objectivepgp_X509v3_add_ext
%xdefine _objectivepgp_X509v3_delete_ext BORINGSSL_PREFIX %+ __objectivepgp_X509v3_delete_ext
%xdefine _objectivepgp_X509v3_get_ext BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext
%xdefine _objectivepgp_X509v3_get_ext_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_NID
%xdefine _objectivepgp_X509v3_get_ext_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_OBJ
%xdefine _objectivepgp_X509v3_get_ext_by_critical BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_by_critical
%xdefine _objectivepgp_X509v3_get_ext_count BORINGSSL_PREFIX %+ __objectivepgp_X509v3_get_ext_count
%xdefine _objectivepgp_X509_CRL_diff BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_diff
%xdefine _objectivepgp_X509_STORE_CTX_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_cleanup
%xdefine _objectivepgp_X509_STORE_CTX_free BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_free
%xdefine _objectivepgp_X509_STORE_CTX_get0_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_cert
%xdefine _objectivepgp_X509_STORE_CTX_get0_current_crl BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_current_crl
%xdefine _objectivepgp_X509_STORE_CTX_get0_current_issuer BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_current_issuer
%xdefine _objectivepgp_X509_STORE_CTX_get0_param BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_param
%xdefine _objectivepgp_X509_STORE_CTX_get0_parent_ctx BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_parent_ctx
%xdefine _objectivepgp_X509_STORE_CTX_get0_policy_tree BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_policy_tree
%xdefine _objectivepgp_X509_STORE_CTX_get0_untrusted BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get0_untrusted
%xdefine _objectivepgp_X509_STORE_CTX_get1_chain BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get1_chain
%xdefine _objectivepgp_X509_STORE_CTX_get_chain BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_chain
%xdefine _objectivepgp_X509_STORE_CTX_get_current_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_current_cert
%xdefine _objectivepgp_X509_STORE_CTX_get_error BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_error
%xdefine _objectivepgp_X509_STORE_CTX_get_error_depth BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_error_depth
%xdefine _objectivepgp_X509_STORE_CTX_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_ex_data
%xdefine _objectivepgp_X509_STORE_CTX_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_ex_new_index
%xdefine _objectivepgp_X509_STORE_CTX_get_explicit_policy BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_get_explicit_policy
%xdefine _objectivepgp_X509_STORE_CTX_init BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_init
%xdefine _objectivepgp_X509_STORE_CTX_new BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_new
%xdefine _objectivepgp_X509_STORE_CTX_purpose_inherit BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_purpose_inherit
%xdefine _objectivepgp_X509_STORE_CTX_set0_crls BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set0_crls
%xdefine _objectivepgp_X509_STORE_CTX_set0_param BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set0_param
%xdefine _objectivepgp_X509_STORE_CTX_set_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_cert
%xdefine _objectivepgp_X509_STORE_CTX_set_chain BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_chain
%xdefine _objectivepgp_X509_STORE_CTX_set_default BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_default
%xdefine _objectivepgp_X509_STORE_CTX_set_depth BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_depth
%xdefine _objectivepgp_X509_STORE_CTX_set_error BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_error
%xdefine _objectivepgp_X509_STORE_CTX_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_ex_data
%xdefine _objectivepgp_X509_STORE_CTX_set_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_flags
%xdefine _objectivepgp_X509_STORE_CTX_set_purpose BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_purpose
%xdefine _objectivepgp_X509_STORE_CTX_set_time BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_time
%xdefine _objectivepgp_X509_STORE_CTX_set_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_trust
%xdefine _objectivepgp_X509_STORE_CTX_set_verify_cb BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_set_verify_cb
%xdefine _objectivepgp_X509_STORE_CTX_trusted_stack BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_trusted_stack
%xdefine _objectivepgp_X509_STORE_CTX_zero BORINGSSL_PREFIX %+ __objectivepgp_X509_STORE_CTX_zero
%xdefine _objectivepgp_X509_cmp_current_time BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp_current_time
%xdefine _objectivepgp_X509_cmp_time BORINGSSL_PREFIX %+ __objectivepgp_X509_cmp_time
%xdefine _objectivepgp_X509_gmtime_adj BORINGSSL_PREFIX %+ __objectivepgp_X509_gmtime_adj
%xdefine _objectivepgp_X509_time_adj BORINGSSL_PREFIX %+ __objectivepgp_X509_time_adj
%xdefine _objectivepgp_X509_time_adj_ex BORINGSSL_PREFIX %+ __objectivepgp_X509_time_adj_ex
%xdefine _objectivepgp_X509_verify_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_verify_cert
%xdefine _objectivepgp_X509_VERIFY_PARAM_add0_policy BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add0_policy
%xdefine _objectivepgp_X509_VERIFY_PARAM_add0_table BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add0_table
%xdefine _objectivepgp_X509_VERIFY_PARAM_add1_host BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_add1_host
%xdefine _objectivepgp_X509_VERIFY_PARAM_clear_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_clear_flags
%xdefine _objectivepgp_X509_VERIFY_PARAM_free BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_free
%xdefine _objectivepgp_X509_VERIFY_PARAM_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0
%xdefine _objectivepgp_X509_VERIFY_PARAM_get0_name BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0_name
%xdefine _objectivepgp_X509_VERIFY_PARAM_get0_peername BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get0_peername
%xdefine _objectivepgp_X509_VERIFY_PARAM_get_count BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_count
%xdefine _objectivepgp_X509_VERIFY_PARAM_get_depth BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_depth
%xdefine _objectivepgp_X509_VERIFY_PARAM_get_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_get_flags
%xdefine _objectivepgp_X509_VERIFY_PARAM_inherit BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_inherit
%xdefine _objectivepgp_X509_VERIFY_PARAM_lookup BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_lookup
%xdefine _objectivepgp_X509_VERIFY_PARAM_new BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_new
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1 BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_email BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_email
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_host BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_host
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_ip BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_ip
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_ip_asc BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_ip_asc
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_name BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_name
%xdefine _objectivepgp_X509_VERIFY_PARAM_set1_policies BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set1_policies
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_depth BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_depth
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_flags
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_hostflags BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_hostflags
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_purpose BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_purpose
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_time BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_time
%xdefine _objectivepgp_X509_VERIFY_PARAM_set_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_set_trust
%xdefine _objectivepgp_X509_VERIFY_PARAM_table_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_VERIFY_PARAM_table_cleanup
%xdefine _objectivepgp_X509_CRL_get0_lastUpdate BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_lastUpdate
%xdefine _objectivepgp_X509_CRL_get0_nextUpdate BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_nextUpdate
%xdefine _objectivepgp_X509_CRL_get0_signature BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_signature
%xdefine _objectivepgp_X509_CRL_get_signature_nid BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_signature_nid
%xdefine _objectivepgp_X509_CRL_set_issuer_name BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_issuer_name
%xdefine _objectivepgp_X509_CRL_set_lastUpdate BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_lastUpdate
%xdefine _objectivepgp_X509_CRL_set_nextUpdate BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_nextUpdate
%xdefine _objectivepgp_X509_CRL_set_version BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_version
%xdefine _objectivepgp_X509_CRL_sort BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sort
%xdefine _objectivepgp_X509_CRL_up_ref BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_up_ref
%xdefine _objectivepgp_X509_REVOKED_get0_revocationDate BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get0_revocationDate
%xdefine _objectivepgp_X509_REVOKED_get0_serialNumber BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_get0_serialNumber
%xdefine _objectivepgp_X509_REVOKED_set_revocationDate BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_set_revocationDate
%xdefine _objectivepgp_X509_REVOKED_set_serialNumber BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_set_serialNumber
%xdefine _objectivepgp_i2d_re_X509_CRL_tbs BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_CRL_tbs
%xdefine _objectivepgp_X509_NAME_ENTRY_create_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_NID
%xdefine _objectivepgp_X509_NAME_ENTRY_create_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_OBJ
%xdefine _objectivepgp_X509_NAME_ENTRY_create_by_txt BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_create_by_txt
%xdefine _objectivepgp_X509_NAME_ENTRY_get_data BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_get_data
%xdefine _objectivepgp_X509_NAME_ENTRY_get_object BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_get_object
%xdefine _objectivepgp_X509_NAME_ENTRY_set_data BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set_data
%xdefine _objectivepgp_X509_NAME_ENTRY_set_object BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set_object
%xdefine _objectivepgp_X509_NAME_add_entry BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry
%xdefine _objectivepgp_X509_NAME_add_entry_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_NID
%xdefine _objectivepgp_X509_NAME_add_entry_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_OBJ
%xdefine _objectivepgp_X509_NAME_add_entry_by_txt BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_add_entry_by_txt
%xdefine _objectivepgp_X509_NAME_delete_entry BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_delete_entry
%xdefine _objectivepgp_X509_NAME_entry_count BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_entry_count
%xdefine _objectivepgp_X509_NAME_get_entry BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_entry
%xdefine _objectivepgp_X509_NAME_get_index_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_index_by_NID
%xdefine _objectivepgp_X509_NAME_get_index_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_index_by_OBJ
%xdefine _objectivepgp_X509_NAME_get_text_by_NID BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_text_by_NID
%xdefine _objectivepgp_X509_NAME_get_text_by_OBJ BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get_text_by_OBJ
%xdefine _objectivepgp_X509_REQ_set_pubkey BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_pubkey
%xdefine _objectivepgp_X509_REQ_set_subject_name BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_subject_name
%xdefine _objectivepgp_X509_REQ_set_version BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_set_version
%xdefine _objectivepgp_NETSCAPE_SPKI_b64_decode BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_b64_decode
%xdefine _objectivepgp_NETSCAPE_SPKI_b64_encode BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_b64_encode
%xdefine _objectivepgp_NETSCAPE_SPKI_get_pubkey BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_get_pubkey
%xdefine _objectivepgp_NETSCAPE_SPKI_set_pubkey BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_set_pubkey
%xdefine _objectivepgp_X509_ALGORS_it BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGORS_it
%xdefine _objectivepgp_X509_ALGOR_cmp BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_cmp
%xdefine _objectivepgp_X509_ALGOR_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_dup
%xdefine _objectivepgp_X509_ALGOR_free BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_free
%xdefine _objectivepgp_X509_ALGOR_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_get0
%xdefine _objectivepgp_X509_ALGOR_it BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_it
%xdefine _objectivepgp_X509_ALGOR_new BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_new
%xdefine _objectivepgp_X509_ALGOR_set0 BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_set0
%xdefine _objectivepgp_X509_ALGOR_set_md BORINGSSL_PREFIX %+ __objectivepgp_X509_ALGOR_set_md
%xdefine _objectivepgp_d2i_X509_ALGOR BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ALGOR
%xdefine _objectivepgp_d2i_X509_ALGORS BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ALGORS
%xdefine _objectivepgp_i2d_X509_ALGOR BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ALGOR
%xdefine _objectivepgp_i2d_X509_ALGORS BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ALGORS
%xdefine _objectivepgp_NETSCAPE_SPKI_sign BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_sign
%xdefine _objectivepgp_NETSCAPE_SPKI_verify BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_verify
%xdefine _objectivepgp_X509_CRL_digest BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_digest
%xdefine _objectivepgp_X509_CRL_sign BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sign
%xdefine _objectivepgp_X509_CRL_sign_ctx BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_sign_ctx
%xdefine _objectivepgp_X509_NAME_digest BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_digest
%xdefine _objectivepgp_X509_REQ_digest BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_digest
%xdefine _objectivepgp_X509_REQ_sign BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_sign
%xdefine _objectivepgp_X509_REQ_sign_ctx BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_sign_ctx
%xdefine _objectivepgp_X509_REQ_verify BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_verify
%xdefine _objectivepgp_X509_digest BORINGSSL_PREFIX %+ __objectivepgp_X509_digest
%xdefine _objectivepgp_X509_pubkey_digest BORINGSSL_PREFIX %+ __objectivepgp_X509_pubkey_digest
%xdefine _objectivepgp_X509_sign BORINGSSL_PREFIX %+ __objectivepgp_X509_sign
%xdefine _objectivepgp_X509_sign_ctx BORINGSSL_PREFIX %+ __objectivepgp_X509_sign_ctx
%xdefine _objectivepgp_X509_verify BORINGSSL_PREFIX %+ __objectivepgp_X509_verify
%xdefine _objectivepgp_d2i_DHparams_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_DHparams_bio
%xdefine _objectivepgp_d2i_DSAPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey_bio
%xdefine _objectivepgp_d2i_DSAPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSAPrivateKey_fp
%xdefine _objectivepgp_d2i_DSA_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY_bio
%xdefine _objectivepgp_d2i_DSA_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY_fp
%xdefine _objectivepgp_d2i_ECPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey_bio
%xdefine _objectivepgp_d2i_ECPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_ECPrivateKey_fp
%xdefine _objectivepgp_d2i_EC_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY_bio
%xdefine _objectivepgp_d2i_EC_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY_fp
%xdefine _objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_bio
%xdefine _objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_PRIV_KEY_INFO_fp
%xdefine _objectivepgp_d2i_PKCS8_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_bio
%xdefine _objectivepgp_d2i_PKCS8_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKCS8_fp
%xdefine _objectivepgp_d2i_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY_bio
%xdefine _objectivepgp_d2i_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY_fp
%xdefine _objectivepgp_d2i_PrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey_bio
%xdefine _objectivepgp_d2i_PrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_PrivateKey_fp
%xdefine _objectivepgp_d2i_RSAPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey_bio
%xdefine _objectivepgp_d2i_RSAPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPrivateKey_fp
%xdefine _objectivepgp_d2i_RSAPublicKey_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey_bio
%xdefine _objectivepgp_d2i_RSAPublicKey_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSAPublicKey_fp
%xdefine _objectivepgp_d2i_RSA_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY_bio
%xdefine _objectivepgp_d2i_RSA_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY_fp
%xdefine _objectivepgp_d2i_X509_CRL_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_bio
%xdefine _objectivepgp_d2i_X509_CRL_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_fp
%xdefine _objectivepgp_d2i_X509_REQ_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_bio
%xdefine _objectivepgp_d2i_X509_REQ_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_fp
%xdefine _objectivepgp_d2i_X509_bio BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_bio
%xdefine _objectivepgp_d2i_X509_fp BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_fp
%xdefine _objectivepgp_i2d_DHparams_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_DHparams_bio
%xdefine _objectivepgp_i2d_DSAPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey_bio
%xdefine _objectivepgp_i2d_DSAPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSAPrivateKey_fp
%xdefine _objectivepgp_i2d_DSA_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY_bio
%xdefine _objectivepgp_i2d_DSA_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY_fp
%xdefine _objectivepgp_i2d_ECPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey_bio
%xdefine _objectivepgp_i2d_ECPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_ECPrivateKey_fp
%xdefine _objectivepgp_i2d_EC_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY_bio
%xdefine _objectivepgp_i2d_EC_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY_fp
%xdefine _objectivepgp_i2d_PKCS8PrivateKeyInfo_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKeyInfo_bio
%xdefine _objectivepgp_i2d_PKCS8PrivateKeyInfo_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8PrivateKeyInfo_fp
%xdefine _objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_bio
%xdefine _objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_PRIV_KEY_INFO_fp
%xdefine _objectivepgp_i2d_PKCS8_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_bio
%xdefine _objectivepgp_i2d_PKCS8_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKCS8_fp
%xdefine _objectivepgp_i2d_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY_bio
%xdefine _objectivepgp_i2d_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY_fp
%xdefine _objectivepgp_i2d_PrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey_bio
%xdefine _objectivepgp_i2d_PrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_PrivateKey_fp
%xdefine _objectivepgp_i2d_RSAPrivateKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey_bio
%xdefine _objectivepgp_i2d_RSAPrivateKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPrivateKey_fp
%xdefine _objectivepgp_i2d_RSAPublicKey_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey_bio
%xdefine _objectivepgp_i2d_RSAPublicKey_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSAPublicKey_fp
%xdefine _objectivepgp_i2d_RSA_PUBKEY_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY_bio
%xdefine _objectivepgp_i2d_RSA_PUBKEY_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY_fp
%xdefine _objectivepgp_i2d_X509_CRL_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_bio
%xdefine _objectivepgp_i2d_X509_CRL_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_fp
%xdefine _objectivepgp_i2d_X509_REQ_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_bio
%xdefine _objectivepgp_i2d_X509_REQ_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_fp
%xdefine _objectivepgp_i2d_X509_bio BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_bio
%xdefine _objectivepgp_i2d_X509_fp BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_fp
%xdefine _objectivepgp_X509_ATTRIBUTE_SET_it BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_SET_it
%xdefine _objectivepgp_X509_ATTRIBUTE_create BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_create
%xdefine _objectivepgp_X509_ATTRIBUTE_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_dup
%xdefine _objectivepgp_X509_ATTRIBUTE_free BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_free
%xdefine _objectivepgp_X509_ATTRIBUTE_it BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_it
%xdefine _objectivepgp_X509_ATTRIBUTE_new BORINGSSL_PREFIX %+ __objectivepgp_X509_ATTRIBUTE_new
%xdefine _objectivepgp_d2i_X509_ATTRIBUTE BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_ATTRIBUTE
%xdefine _objectivepgp_i2d_X509_ATTRIBUTE BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_ATTRIBUTE
%xdefine _objectivepgp_X509_CRL_INFO_free BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_free
%xdefine _objectivepgp_X509_CRL_INFO_it BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_it
%xdefine _objectivepgp_X509_CRL_INFO_new BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_INFO_new
%xdefine _objectivepgp_X509_CRL_METHOD_free BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_METHOD_free
%xdefine _objectivepgp_X509_CRL_METHOD_new BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_METHOD_new
%xdefine _objectivepgp_X509_CRL_add0_revoked BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_add0_revoked
%xdefine _objectivepgp_X509_CRL_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_dup
%xdefine _objectivepgp_X509_CRL_free BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_free
%xdefine _objectivepgp_X509_CRL_get0_by_cert BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_by_cert
%xdefine _objectivepgp_X509_CRL_get0_by_serial BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get0_by_serial
%xdefine _objectivepgp_X509_CRL_get_meth_data BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_get_meth_data
%xdefine _objectivepgp_X509_CRL_it BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_it
%xdefine _objectivepgp_X509_CRL_new BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_new
%xdefine _objectivepgp_X509_CRL_set_default_method BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_default_method
%xdefine _objectivepgp_X509_CRL_set_meth_data BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_set_meth_data
%xdefine _objectivepgp_X509_CRL_verify BORINGSSL_PREFIX %+ __objectivepgp_X509_CRL_verify
%xdefine _objectivepgp_X509_REVOKED_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_dup
%xdefine _objectivepgp_X509_REVOKED_free BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_free
%xdefine _objectivepgp_X509_REVOKED_it BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_it
%xdefine _objectivepgp_X509_REVOKED_new BORINGSSL_PREFIX %+ __objectivepgp_X509_REVOKED_new
%xdefine _objectivepgp_d2i_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL
%xdefine _objectivepgp_d2i_X509_CRL_INFO BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CRL_INFO
%xdefine _objectivepgp_d2i_X509_REVOKED BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REVOKED
%xdefine _objectivepgp_i2d_X509_CRL BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL
%xdefine _objectivepgp_i2d_X509_CRL_INFO BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CRL_INFO
%xdefine _objectivepgp_i2d_X509_REVOKED BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REVOKED
%xdefine _objectivepgp_X509_EXTENSIONS_it BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSIONS_it
%xdefine _objectivepgp_X509_EXTENSION_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_dup
%xdefine _objectivepgp_X509_EXTENSION_free BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_free
%xdefine _objectivepgp_X509_EXTENSION_it BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_it
%xdefine _objectivepgp_X509_EXTENSION_new BORINGSSL_PREFIX %+ __objectivepgp_X509_EXTENSION_new
%xdefine _objectivepgp_d2i_X509_EXTENSION BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_EXTENSION
%xdefine _objectivepgp_d2i_X509_EXTENSIONS BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_EXTENSIONS
%xdefine _objectivepgp_i2d_X509_EXTENSION BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_EXTENSION
%xdefine _objectivepgp_i2d_X509_EXTENSIONS BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_EXTENSIONS
%xdefine _objectivepgp_X509_INFO_free BORINGSSL_PREFIX %+ __objectivepgp_X509_INFO_free
%xdefine _objectivepgp_X509_INFO_new BORINGSSL_PREFIX %+ __objectivepgp_X509_INFO_new
%xdefine _objectivepgp_X509_NAME_ENTRIES_it BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRIES_it
%xdefine _objectivepgp_X509_NAME_ENTRY_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_dup
%xdefine _objectivepgp_X509_NAME_ENTRY_free BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_free
%xdefine _objectivepgp_X509_NAME_ENTRY_it BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_it
%xdefine _objectivepgp_X509_NAME_ENTRY_new BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_new
%xdefine _objectivepgp_X509_NAME_ENTRY_set BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_ENTRY_set
%xdefine _objectivepgp_X509_NAME_INTERNAL_it BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_INTERNAL_it
%xdefine _objectivepgp_X509_NAME_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_dup
%xdefine _objectivepgp_X509_NAME_free BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_free
%xdefine _objectivepgp_X509_NAME_get0_der BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_get0_der
%xdefine _objectivepgp_X509_NAME_it BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_it
%xdefine _objectivepgp_X509_NAME_new BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_new
%xdefine _objectivepgp_X509_NAME_set BORINGSSL_PREFIX %+ __objectivepgp_X509_NAME_set
%xdefine _objectivepgp_d2i_X509_NAME BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_NAME
%xdefine _objectivepgp_d2i_X509_NAME_ENTRY BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_NAME_ENTRY
%xdefine _objectivepgp_i2d_X509_NAME BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_NAME
%xdefine _objectivepgp_i2d_X509_NAME_ENTRY BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_NAME_ENTRY
%xdefine _objectivepgp_X509_PKEY_free BORINGSSL_PREFIX %+ __objectivepgp_X509_PKEY_free
%xdefine _objectivepgp_X509_PKEY_new BORINGSSL_PREFIX %+ __objectivepgp_X509_PKEY_new
%xdefine _objectivepgp_X509_PUBKEY_free BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_free
%xdefine _objectivepgp_X509_PUBKEY_get BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_get
%xdefine _objectivepgp_X509_PUBKEY_get0_param BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_get0_param
%xdefine _objectivepgp_X509_PUBKEY_it BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_it
%xdefine _objectivepgp_X509_PUBKEY_new BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_new
%xdefine _objectivepgp_X509_PUBKEY_set BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_set
%xdefine _objectivepgp_X509_PUBKEY_set0_param BORINGSSL_PREFIX %+ __objectivepgp_X509_PUBKEY_set0_param
%xdefine _objectivepgp_d2i_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_d2i_DSA_PUBKEY
%xdefine _objectivepgp_d2i_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_d2i_EC_PUBKEY
%xdefine _objectivepgp_d2i_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_d2i_PUBKEY
%xdefine _objectivepgp_d2i_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_d2i_RSA_PUBKEY
%xdefine _objectivepgp_d2i_X509_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_PUBKEY
%xdefine _objectivepgp_i2d_DSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_i2d_DSA_PUBKEY
%xdefine _objectivepgp_i2d_EC_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_i2d_EC_PUBKEY
%xdefine _objectivepgp_i2d_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_i2d_PUBKEY
%xdefine _objectivepgp_i2d_RSA_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_i2d_RSA_PUBKEY
%xdefine _objectivepgp_i2d_X509_PUBKEY BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_PUBKEY
%xdefine _objectivepgp_X509_REQ_INFO_free BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_free
%xdefine _objectivepgp_X509_REQ_INFO_it BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_it
%xdefine _objectivepgp_X509_REQ_INFO_new BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_INFO_new
%xdefine _objectivepgp_X509_REQ_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_dup
%xdefine _objectivepgp_X509_REQ_free BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_free
%xdefine _objectivepgp_X509_REQ_it BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_it
%xdefine _objectivepgp_X509_REQ_new BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_new
%xdefine _objectivepgp_d2i_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ
%xdefine _objectivepgp_d2i_X509_REQ_INFO BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_REQ_INFO
%xdefine _objectivepgp_i2d_X509_REQ BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ
%xdefine _objectivepgp_i2d_X509_REQ_INFO BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_REQ_INFO
%xdefine _objectivepgp_X509_SIG_free BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_free
%xdefine _objectivepgp_X509_SIG_it BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_it
%xdefine _objectivepgp_X509_SIG_new BORINGSSL_PREFIX %+ __objectivepgp_X509_SIG_new
%xdefine _objectivepgp_d2i_X509_SIG BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_SIG
%xdefine _objectivepgp_i2d_X509_SIG BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_SIG
%xdefine _objectivepgp_NETSCAPE_SPKAC_free BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_free
%xdefine _objectivepgp_NETSCAPE_SPKAC_it BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_it
%xdefine _objectivepgp_NETSCAPE_SPKAC_new BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKAC_new
%xdefine _objectivepgp_NETSCAPE_SPKI_free BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_free
%xdefine _objectivepgp_NETSCAPE_SPKI_it BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_it
%xdefine _objectivepgp_NETSCAPE_SPKI_new BORINGSSL_PREFIX %+ __objectivepgp_NETSCAPE_SPKI_new
%xdefine _objectivepgp_d2i_NETSCAPE_SPKAC BORINGSSL_PREFIX %+ __objectivepgp_d2i_NETSCAPE_SPKAC
%xdefine _objectivepgp_d2i_NETSCAPE_SPKI BORINGSSL_PREFIX %+ __objectivepgp_d2i_NETSCAPE_SPKI
%xdefine _objectivepgp_i2d_NETSCAPE_SPKAC BORINGSSL_PREFIX %+ __objectivepgp_i2d_NETSCAPE_SPKAC
%xdefine _objectivepgp_i2d_NETSCAPE_SPKI BORINGSSL_PREFIX %+ __objectivepgp_i2d_NETSCAPE_SPKI
%xdefine _objectivepgp_X509_VAL_free BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_free
%xdefine _objectivepgp_X509_VAL_it BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_it
%xdefine _objectivepgp_X509_VAL_new BORINGSSL_PREFIX %+ __objectivepgp_X509_VAL_new
%xdefine _objectivepgp_d2i_X509_VAL BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_VAL
%xdefine _objectivepgp_i2d_X509_VAL BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_VAL
%xdefine _objectivepgp_X509_CINF_free BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_free
%xdefine _objectivepgp_X509_CINF_it BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_it
%xdefine _objectivepgp_X509_CINF_new BORINGSSL_PREFIX %+ __objectivepgp_X509_CINF_new
%xdefine _objectivepgp_X509_dup BORINGSSL_PREFIX %+ __objectivepgp_X509_dup
%xdefine _objectivepgp_X509_free BORINGSSL_PREFIX %+ __objectivepgp_X509_free
%xdefine _objectivepgp_X509_get0_signature BORINGSSL_PREFIX %+ __objectivepgp_X509_get0_signature
%xdefine _objectivepgp_X509_get_ex_data BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ex_data
%xdefine _objectivepgp_X509_get_ex_new_index BORINGSSL_PREFIX %+ __objectivepgp_X509_get_ex_new_index
%xdefine _objectivepgp_X509_get_signature_nid BORINGSSL_PREFIX %+ __objectivepgp_X509_get_signature_nid
%xdefine _objectivepgp_X509_it BORINGSSL_PREFIX %+ __objectivepgp_X509_it
%xdefine _objectivepgp_X509_new BORINGSSL_PREFIX %+ __objectivepgp_X509_new
%xdefine _objectivepgp_X509_parse_from_buffer BORINGSSL_PREFIX %+ __objectivepgp_X509_parse_from_buffer
%xdefine _objectivepgp_X509_set_ex_data BORINGSSL_PREFIX %+ __objectivepgp_X509_set_ex_data
%xdefine _objectivepgp_X509_up_ref BORINGSSL_PREFIX %+ __objectivepgp_X509_up_ref
%xdefine _objectivepgp_d2i_X509 BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509
%xdefine _objectivepgp_d2i_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_AUX
%xdefine _objectivepgp_d2i_X509_CINF BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CINF
%xdefine _objectivepgp_i2d_X509 BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509
%xdefine _objectivepgp_i2d_X509_AUX BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_AUX
%xdefine _objectivepgp_i2d_X509_CINF BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CINF
%xdefine _objectivepgp_i2d_re_X509_tbs BORINGSSL_PREFIX %+ __objectivepgp_i2d_re_X509_tbs
%xdefine _objectivepgp_X509_CERT_AUX_free BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_free
%xdefine _objectivepgp_X509_CERT_AUX_it BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_it
%xdefine _objectivepgp_X509_CERT_AUX_new BORINGSSL_PREFIX %+ __objectivepgp_X509_CERT_AUX_new
%xdefine _objectivepgp_X509_add1_reject_object BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_reject_object
%xdefine _objectivepgp_X509_add1_trust_object BORINGSSL_PREFIX %+ __objectivepgp_X509_add1_trust_object
%xdefine _objectivepgp_X509_alias_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_alias_get0
%xdefine _objectivepgp_X509_alias_set1 BORINGSSL_PREFIX %+ __objectivepgp_X509_alias_set1
%xdefine _objectivepgp_X509_keyid_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_keyid_get0
%xdefine _objectivepgp_X509_keyid_set1 BORINGSSL_PREFIX %+ __objectivepgp_X509_keyid_set1
%xdefine _objectivepgp_X509_reject_clear BORINGSSL_PREFIX %+ __objectivepgp_X509_reject_clear
%xdefine _objectivepgp_X509_trust_clear BORINGSSL_PREFIX %+ __objectivepgp_X509_trust_clear
%xdefine _objectivepgp_d2i_X509_CERT_AUX BORINGSSL_PREFIX %+ __objectivepgp_d2i_X509_CERT_AUX
%xdefine _objectivepgp_i2d_X509_CERT_AUX BORINGSSL_PREFIX %+ __objectivepgp_i2d_X509_CERT_AUX
%xdefine _objectivepgp_policy_cache_find_data BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_find_data
%xdefine _objectivepgp_policy_cache_free BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_free
%xdefine _objectivepgp_policy_cache_set BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_set
%xdefine _objectivepgp_policy_data_free BORINGSSL_PREFIX %+ __objectivepgp_policy_data_free
%xdefine _objectivepgp_policy_data_new BORINGSSL_PREFIX %+ __objectivepgp_policy_data_new
%xdefine _objectivepgp_X509_policy_level_get0_node BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_level_get0_node
%xdefine _objectivepgp_X509_policy_level_node_count BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_level_node_count
%xdefine _objectivepgp_X509_policy_node_get0_parent BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_parent
%xdefine _objectivepgp_X509_policy_node_get0_policy BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_policy
%xdefine _objectivepgp_X509_policy_node_get0_qualifiers BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_node_get0_qualifiers
%xdefine _objectivepgp_X509_policy_tree_get0_level BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_level
%xdefine _objectivepgp_X509_policy_tree_get0_policies BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_policies
%xdefine _objectivepgp_X509_policy_tree_get0_user_policies BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_get0_user_policies
%xdefine _objectivepgp_X509_policy_tree_level_count BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_level_count
%xdefine _objectivepgp_policy_cache_set_mapping BORINGSSL_PREFIX %+ __objectivepgp_policy_cache_set_mapping
%xdefine _objectivepgp_level_add_node BORINGSSL_PREFIX %+ __objectivepgp_level_add_node
%xdefine _objectivepgp_level_find_node BORINGSSL_PREFIX %+ __objectivepgp_level_find_node
%xdefine _objectivepgp_policy_node_cmp_new BORINGSSL_PREFIX %+ __objectivepgp_policy_node_cmp_new
%xdefine _objectivepgp_policy_node_free BORINGSSL_PREFIX %+ __objectivepgp_policy_node_free
%xdefine _objectivepgp_policy_node_match BORINGSSL_PREFIX %+ __objectivepgp_policy_node_match
%xdefine _objectivepgp_tree_find_sk BORINGSSL_PREFIX %+ __objectivepgp_tree_find_sk
%xdefine _objectivepgp_X509_policy_check BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_check
%xdefine _objectivepgp_X509_policy_tree_free BORINGSSL_PREFIX %+ __objectivepgp_X509_policy_tree_free
%xdefine _objectivepgp_v3_akey_id BORINGSSL_PREFIX %+ __objectivepgp_v3_akey_id
%xdefine _objectivepgp_AUTHORITY_KEYID_free BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_free
%xdefine _objectivepgp_AUTHORITY_KEYID_it BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_it
%xdefine _objectivepgp_AUTHORITY_KEYID_new BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_KEYID_new
%xdefine _objectivepgp_d2i_AUTHORITY_KEYID BORINGSSL_PREFIX %+ __objectivepgp_d2i_AUTHORITY_KEYID
%xdefine _objectivepgp_i2d_AUTHORITY_KEYID BORINGSSL_PREFIX %+ __objectivepgp_i2d_AUTHORITY_KEYID
%xdefine _objectivepgp_GENERAL_NAME_print BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_print
%xdefine _objectivepgp_a2i_GENERAL_NAME BORINGSSL_PREFIX %+ __objectivepgp_a2i_GENERAL_NAME
%xdefine _objectivepgp_i2v_GENERAL_NAME BORINGSSL_PREFIX %+ __objectivepgp_i2v_GENERAL_NAME
%xdefine _objectivepgp_i2v_GENERAL_NAMES BORINGSSL_PREFIX %+ __objectivepgp_i2v_GENERAL_NAMES
%xdefine _objectivepgp_v2i_GENERAL_NAME BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAME
%xdefine _objectivepgp_v2i_GENERAL_NAMES BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAMES
%xdefine _objectivepgp_v2i_GENERAL_NAME_ex BORINGSSL_PREFIX %+ __objectivepgp_v2i_GENERAL_NAME_ex
%xdefine _objectivepgp_v3_alt BORINGSSL_PREFIX %+ __objectivepgp_v3_alt
%xdefine _objectivepgp_BASIC_CONSTRAINTS_free BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_free
%xdefine _objectivepgp_BASIC_CONSTRAINTS_it BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_it
%xdefine _objectivepgp_BASIC_CONSTRAINTS_new BORINGSSL_PREFIX %+ __objectivepgp_BASIC_CONSTRAINTS_new
%xdefine _objectivepgp_d2i_BASIC_CONSTRAINTS BORINGSSL_PREFIX %+ __objectivepgp_d2i_BASIC_CONSTRAINTS
%xdefine _objectivepgp_i2d_BASIC_CONSTRAINTS BORINGSSL_PREFIX %+ __objectivepgp_i2d_BASIC_CONSTRAINTS
%xdefine _objectivepgp_v3_bcons BORINGSSL_PREFIX %+ __objectivepgp_v3_bcons
%xdefine _objectivepgp_i2v_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2v_ASN1_BIT_STRING
%xdefine _objectivepgp_v2i_ASN1_BIT_STRING BORINGSSL_PREFIX %+ __objectivepgp_v2i_ASN1_BIT_STRING
%xdefine _objectivepgp_v3_key_usage BORINGSSL_PREFIX %+ __objectivepgp_v3_key_usage
%xdefine _objectivepgp_v3_nscert BORINGSSL_PREFIX %+ __objectivepgp_v3_nscert
%xdefine _objectivepgp_X509V3_EXT_CRL_add_nconf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_CRL_add_nconf
%xdefine _objectivepgp_X509V3_EXT_REQ_add_nconf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_REQ_add_nconf
%xdefine _objectivepgp_X509V3_EXT_add_nconf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_nconf
%xdefine _objectivepgp_X509V3_EXT_add_nconf_sk BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_nconf_sk
%xdefine _objectivepgp_X509V3_EXT_i2d BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_i2d
%xdefine _objectivepgp_X509V3_EXT_nconf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_nconf
%xdefine _objectivepgp_X509V3_EXT_nconf_nid BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_nconf_nid
%xdefine _objectivepgp_X509V3_get_section BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_section
%xdefine _objectivepgp_X509V3_get_string BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_string
%xdefine _objectivepgp_X509V3_section_free BORINGSSL_PREFIX %+ __objectivepgp_X509V3_section_free
%xdefine _objectivepgp_X509V3_set_ctx BORINGSSL_PREFIX %+ __objectivepgp_X509V3_set_ctx
%xdefine _objectivepgp_X509V3_set_nconf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_set_nconf
%xdefine _objectivepgp_X509V3_string_free BORINGSSL_PREFIX %+ __objectivepgp_X509V3_string_free
%xdefine _objectivepgp_CERTIFICATEPOLICIES_free BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_free
%xdefine _objectivepgp_CERTIFICATEPOLICIES_it BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_it
%xdefine _objectivepgp_CERTIFICATEPOLICIES_new BORINGSSL_PREFIX %+ __objectivepgp_CERTIFICATEPOLICIES_new
%xdefine _objectivepgp_NOTICEREF_free BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_free
%xdefine _objectivepgp_NOTICEREF_it BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_it
%xdefine _objectivepgp_NOTICEREF_new BORINGSSL_PREFIX %+ __objectivepgp_NOTICEREF_new
%xdefine _objectivepgp_POLICYINFO_free BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_free
%xdefine _objectivepgp_POLICYINFO_it BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_it
%xdefine _objectivepgp_POLICYINFO_new BORINGSSL_PREFIX %+ __objectivepgp_POLICYINFO_new
%xdefine _objectivepgp_POLICYQUALINFO_free BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_free
%xdefine _objectivepgp_POLICYQUALINFO_it BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_it
%xdefine _objectivepgp_POLICYQUALINFO_new BORINGSSL_PREFIX %+ __objectivepgp_POLICYQUALINFO_new
%xdefine _objectivepgp_USERNOTICE_free BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_free
%xdefine _objectivepgp_USERNOTICE_it BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_it
%xdefine _objectivepgp_USERNOTICE_new BORINGSSL_PREFIX %+ __objectivepgp_USERNOTICE_new
%xdefine _objectivepgp_X509_POLICY_NODE_print BORINGSSL_PREFIX %+ __objectivepgp_X509_POLICY_NODE_print
%xdefine _objectivepgp_d2i_CERTIFICATEPOLICIES BORINGSSL_PREFIX %+ __objectivepgp_d2i_CERTIFICATEPOLICIES
%xdefine _objectivepgp_d2i_NOTICEREF BORINGSSL_PREFIX %+ __objectivepgp_d2i_NOTICEREF
%xdefine _objectivepgp_d2i_POLICYINFO BORINGSSL_PREFIX %+ __objectivepgp_d2i_POLICYINFO
%xdefine _objectivepgp_d2i_POLICYQUALINFO BORINGSSL_PREFIX %+ __objectivepgp_d2i_POLICYQUALINFO
%xdefine _objectivepgp_d2i_USERNOTICE BORINGSSL_PREFIX %+ __objectivepgp_d2i_USERNOTICE
%xdefine _objectivepgp_i2d_CERTIFICATEPOLICIES BORINGSSL_PREFIX %+ __objectivepgp_i2d_CERTIFICATEPOLICIES
%xdefine _objectivepgp_i2d_NOTICEREF BORINGSSL_PREFIX %+ __objectivepgp_i2d_NOTICEREF
%xdefine _objectivepgp_i2d_POLICYINFO BORINGSSL_PREFIX %+ __objectivepgp_i2d_POLICYINFO
%xdefine _objectivepgp_i2d_POLICYQUALINFO BORINGSSL_PREFIX %+ __objectivepgp_i2d_POLICYQUALINFO
%xdefine _objectivepgp_i2d_USERNOTICE BORINGSSL_PREFIX %+ __objectivepgp_i2d_USERNOTICE
%xdefine _objectivepgp_v3_cpols BORINGSSL_PREFIX %+ __objectivepgp_v3_cpols
%xdefine _objectivepgp_CRL_DIST_POINTS_free BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_free
%xdefine _objectivepgp_CRL_DIST_POINTS_it BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_it
%xdefine _objectivepgp_CRL_DIST_POINTS_new BORINGSSL_PREFIX %+ __objectivepgp_CRL_DIST_POINTS_new
%xdefine _objectivepgp_DIST_POINT_NAME_free BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_free
%xdefine _objectivepgp_DIST_POINT_NAME_it BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_it
%xdefine _objectivepgp_DIST_POINT_NAME_new BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_NAME_new
%xdefine _objectivepgp_DIST_POINT_free BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_free
%xdefine _objectivepgp_DIST_POINT_it BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_it
%xdefine _objectivepgp_DIST_POINT_new BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_new
%xdefine _objectivepgp_DIST_POINT_set_dpname BORINGSSL_PREFIX %+ __objectivepgp_DIST_POINT_set_dpname
%xdefine _objectivepgp_ISSUING_DIST_POINT_free BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_free
%xdefine _objectivepgp_ISSUING_DIST_POINT_it BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_it
%xdefine _objectivepgp_ISSUING_DIST_POINT_new BORINGSSL_PREFIX %+ __objectivepgp_ISSUING_DIST_POINT_new
%xdefine _objectivepgp_d2i_CRL_DIST_POINTS BORINGSSL_PREFIX %+ __objectivepgp_d2i_CRL_DIST_POINTS
%xdefine _objectivepgp_d2i_DIST_POINT BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIST_POINT
%xdefine _objectivepgp_d2i_DIST_POINT_NAME BORINGSSL_PREFIX %+ __objectivepgp_d2i_DIST_POINT_NAME
%xdefine _objectivepgp_d2i_ISSUING_DIST_POINT BORINGSSL_PREFIX %+ __objectivepgp_d2i_ISSUING_DIST_POINT
%xdefine _objectivepgp_i2d_CRL_DIST_POINTS BORINGSSL_PREFIX %+ __objectivepgp_i2d_CRL_DIST_POINTS
%xdefine _objectivepgp_i2d_DIST_POINT BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIST_POINT
%xdefine _objectivepgp_i2d_DIST_POINT_NAME BORINGSSL_PREFIX %+ __objectivepgp_i2d_DIST_POINT_NAME
%xdefine _objectivepgp_i2d_ISSUING_DIST_POINT BORINGSSL_PREFIX %+ __objectivepgp_i2d_ISSUING_DIST_POINT
%xdefine _objectivepgp_v3_crld BORINGSSL_PREFIX %+ __objectivepgp_v3_crld
%xdefine _objectivepgp_v3_freshest_crl BORINGSSL_PREFIX %+ __objectivepgp_v3_freshest_crl
%xdefine _objectivepgp_v3_idp BORINGSSL_PREFIX %+ __objectivepgp_v3_idp
%xdefine _objectivepgp_i2s_ASN1_ENUMERATED_TABLE BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_ENUMERATED_TABLE
%xdefine _objectivepgp_v3_crl_reason BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_reason
%xdefine _objectivepgp_EXTENDED_KEY_USAGE_free BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_free
%xdefine _objectivepgp_EXTENDED_KEY_USAGE_it BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_it
%xdefine _objectivepgp_EXTENDED_KEY_USAGE_new BORINGSSL_PREFIX %+ __objectivepgp_EXTENDED_KEY_USAGE_new
%xdefine _objectivepgp_d2i_EXTENDED_KEY_USAGE BORINGSSL_PREFIX %+ __objectivepgp_d2i_EXTENDED_KEY_USAGE
%xdefine _objectivepgp_i2d_EXTENDED_KEY_USAGE BORINGSSL_PREFIX %+ __objectivepgp_i2d_EXTENDED_KEY_USAGE
%xdefine _objectivepgp_v3_ext_ku BORINGSSL_PREFIX %+ __objectivepgp_v3_ext_ku
%xdefine _objectivepgp_v3_ocsp_accresp BORINGSSL_PREFIX %+ __objectivepgp_v3_ocsp_accresp
%xdefine _objectivepgp_EDIPARTYNAME_free BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_free
%xdefine _objectivepgp_EDIPARTYNAME_it BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_it
%xdefine _objectivepgp_EDIPARTYNAME_new BORINGSSL_PREFIX %+ __objectivepgp_EDIPARTYNAME_new
%xdefine _objectivepgp_GENERAL_NAMES_free BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_free
%xdefine _objectivepgp_GENERAL_NAMES_it BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_it
%xdefine _objectivepgp_GENERAL_NAMES_new BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAMES_new
%xdefine _objectivepgp_GENERAL_NAME_cmp BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_cmp
%xdefine _objectivepgp_GENERAL_NAME_dup BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_dup
%xdefine _objectivepgp_GENERAL_NAME_free BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_free
%xdefine _objectivepgp_GENERAL_NAME_get0_otherName BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_get0_otherName
%xdefine _objectivepgp_GENERAL_NAME_get0_value BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_get0_value
%xdefine _objectivepgp_GENERAL_NAME_it BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_it
%xdefine _objectivepgp_GENERAL_NAME_new BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_new
%xdefine _objectivepgp_GENERAL_NAME_set0_othername BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_set0_othername
%xdefine _objectivepgp_GENERAL_NAME_set0_value BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_NAME_set0_value
%xdefine _objectivepgp_OTHERNAME_cmp BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_cmp
%xdefine _objectivepgp_OTHERNAME_free BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_free
%xdefine _objectivepgp_OTHERNAME_it BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_it
%xdefine _objectivepgp_OTHERNAME_new BORINGSSL_PREFIX %+ __objectivepgp_OTHERNAME_new
%xdefine _objectivepgp_d2i_EDIPARTYNAME BORINGSSL_PREFIX %+ __objectivepgp_d2i_EDIPARTYNAME
%xdefine _objectivepgp_d2i_GENERAL_NAME BORINGSSL_PREFIX %+ __objectivepgp_d2i_GENERAL_NAME
%xdefine _objectivepgp_d2i_GENERAL_NAMES BORINGSSL_PREFIX %+ __objectivepgp_d2i_GENERAL_NAMES
%xdefine _objectivepgp_d2i_OTHERNAME BORINGSSL_PREFIX %+ __objectivepgp_d2i_OTHERNAME
%xdefine _objectivepgp_i2d_EDIPARTYNAME BORINGSSL_PREFIX %+ __objectivepgp_i2d_EDIPARTYNAME
%xdefine _objectivepgp_i2d_GENERAL_NAME BORINGSSL_PREFIX %+ __objectivepgp_i2d_GENERAL_NAME
%xdefine _objectivepgp_i2d_GENERAL_NAMES BORINGSSL_PREFIX %+ __objectivepgp_i2d_GENERAL_NAMES
%xdefine _objectivepgp_i2d_OTHERNAME BORINGSSL_PREFIX %+ __objectivepgp_i2d_OTHERNAME
%xdefine _objectivepgp_v3_ns_ia5_list BORINGSSL_PREFIX %+ __objectivepgp_v3_ns_ia5_list
%xdefine _objectivepgp_ACCESS_DESCRIPTION_free BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_free
%xdefine _objectivepgp_ACCESS_DESCRIPTION_it BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_it
%xdefine _objectivepgp_ACCESS_DESCRIPTION_new BORINGSSL_PREFIX %+ __objectivepgp_ACCESS_DESCRIPTION_new
%xdefine _objectivepgp_AUTHORITY_INFO_ACCESS_free BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_free
%xdefine _objectivepgp_AUTHORITY_INFO_ACCESS_it BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_it
%xdefine _objectivepgp_AUTHORITY_INFO_ACCESS_new BORINGSSL_PREFIX %+ __objectivepgp_AUTHORITY_INFO_ACCESS_new
%xdefine _objectivepgp_d2i_ACCESS_DESCRIPTION BORINGSSL_PREFIX %+ __objectivepgp_d2i_ACCESS_DESCRIPTION
%xdefine _objectivepgp_d2i_AUTHORITY_INFO_ACCESS BORINGSSL_PREFIX %+ __objectivepgp_d2i_AUTHORITY_INFO_ACCESS
%xdefine _objectivepgp_i2a_ACCESS_DESCRIPTION BORINGSSL_PREFIX %+ __objectivepgp_i2a_ACCESS_DESCRIPTION
%xdefine _objectivepgp_i2d_ACCESS_DESCRIPTION BORINGSSL_PREFIX %+ __objectivepgp_i2d_ACCESS_DESCRIPTION
%xdefine _objectivepgp_i2d_AUTHORITY_INFO_ACCESS BORINGSSL_PREFIX %+ __objectivepgp_i2d_AUTHORITY_INFO_ACCESS
%xdefine _objectivepgp_v3_info BORINGSSL_PREFIX %+ __objectivepgp_v3_info
%xdefine _objectivepgp_v3_sinfo BORINGSSL_PREFIX %+ __objectivepgp_v3_sinfo
%xdefine _objectivepgp_v3_crl_num BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_num
%xdefine _objectivepgp_v3_delta_crl BORINGSSL_PREFIX %+ __objectivepgp_v3_delta_crl
%xdefine _objectivepgp_v3_inhibit_anyp BORINGSSL_PREFIX %+ __objectivepgp_v3_inhibit_anyp
%xdefine _objectivepgp_X509V3_EXT_add BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add
%xdefine _objectivepgp_X509V3_EXT_add_alias BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_alias
%xdefine _objectivepgp_X509V3_EXT_add_list BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_add_list
%xdefine _objectivepgp_X509V3_EXT_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_cleanup
%xdefine _objectivepgp_X509V3_EXT_d2i BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_d2i
%xdefine _objectivepgp_X509V3_EXT_free BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_free
%xdefine _objectivepgp_X509V3_EXT_get BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_get
%xdefine _objectivepgp_X509V3_EXT_get_nid BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_get_nid
%xdefine _objectivepgp_X509V3_add1_i2d BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add1_i2d
%xdefine _objectivepgp_X509V3_add_standard_extensions BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_standard_extensions
%xdefine _objectivepgp_X509V3_get_d2i BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_d2i
%xdefine _objectivepgp_GENERAL_SUBTREE_free BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_free
%xdefine _objectivepgp_GENERAL_SUBTREE_it BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_it
%xdefine _objectivepgp_GENERAL_SUBTREE_new BORINGSSL_PREFIX %+ __objectivepgp_GENERAL_SUBTREE_new
%xdefine _objectivepgp_NAME_CONSTRAINTS_check BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_check
%xdefine _objectivepgp_NAME_CONSTRAINTS_free BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_free
%xdefine _objectivepgp_NAME_CONSTRAINTS_it BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_it
%xdefine _objectivepgp_NAME_CONSTRAINTS_new BORINGSSL_PREFIX %+ __objectivepgp_NAME_CONSTRAINTS_new
%xdefine _objectivepgp_v3_name_constraints BORINGSSL_PREFIX %+ __objectivepgp_v3_name_constraints
%xdefine _objectivepgp_v3_crl_invdate BORINGSSL_PREFIX %+ __objectivepgp_v3_crl_invdate
%xdefine _objectivepgp_v3_ocsp_nocheck BORINGSSL_PREFIX %+ __objectivepgp_v3_ocsp_nocheck
%xdefine _objectivepgp_v3_pci BORINGSSL_PREFIX %+ __objectivepgp_v3_pci
%xdefine _objectivepgp_PROXY_CERT_INFO_EXTENSION_free BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_free
%xdefine _objectivepgp_PROXY_CERT_INFO_EXTENSION_it BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_it
%xdefine _objectivepgp_PROXY_CERT_INFO_EXTENSION_new BORINGSSL_PREFIX %+ __objectivepgp_PROXY_CERT_INFO_EXTENSION_new
%xdefine _objectivepgp_PROXY_POLICY_free BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_free
%xdefine _objectivepgp_PROXY_POLICY_it BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_it
%xdefine _objectivepgp_PROXY_POLICY_new BORINGSSL_PREFIX %+ __objectivepgp_PROXY_POLICY_new
%xdefine _objectivepgp_d2i_PROXY_CERT_INFO_EXTENSION BORINGSSL_PREFIX %+ __objectivepgp_d2i_PROXY_CERT_INFO_EXTENSION
%xdefine _objectivepgp_d2i_PROXY_POLICY BORINGSSL_PREFIX %+ __objectivepgp_d2i_PROXY_POLICY
%xdefine _objectivepgp_i2d_PROXY_CERT_INFO_EXTENSION BORINGSSL_PREFIX %+ __objectivepgp_i2d_PROXY_CERT_INFO_EXTENSION
%xdefine _objectivepgp_i2d_PROXY_POLICY BORINGSSL_PREFIX %+ __objectivepgp_i2d_PROXY_POLICY
%xdefine _objectivepgp_POLICY_CONSTRAINTS_free BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_free
%xdefine _objectivepgp_POLICY_CONSTRAINTS_it BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_it
%xdefine _objectivepgp_POLICY_CONSTRAINTS_new BORINGSSL_PREFIX %+ __objectivepgp_POLICY_CONSTRAINTS_new
%xdefine _objectivepgp_v3_policy_constraints BORINGSSL_PREFIX %+ __objectivepgp_v3_policy_constraints
%xdefine _objectivepgp_PKEY_USAGE_PERIOD_free BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_free
%xdefine _objectivepgp_PKEY_USAGE_PERIOD_it BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_it
%xdefine _objectivepgp_PKEY_USAGE_PERIOD_new BORINGSSL_PREFIX %+ __objectivepgp_PKEY_USAGE_PERIOD_new
%xdefine _objectivepgp_d2i_PKEY_USAGE_PERIOD BORINGSSL_PREFIX %+ __objectivepgp_d2i_PKEY_USAGE_PERIOD
%xdefine _objectivepgp_i2d_PKEY_USAGE_PERIOD BORINGSSL_PREFIX %+ __objectivepgp_i2d_PKEY_USAGE_PERIOD
%xdefine _objectivepgp_v3_pkey_usage_period BORINGSSL_PREFIX %+ __objectivepgp_v3_pkey_usage_period
%xdefine _objectivepgp_POLICY_MAPPINGS_it BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPINGS_it
%xdefine _objectivepgp_POLICY_MAPPING_free BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_free
%xdefine _objectivepgp_POLICY_MAPPING_it BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_it
%xdefine _objectivepgp_POLICY_MAPPING_new BORINGSSL_PREFIX %+ __objectivepgp_POLICY_MAPPING_new
%xdefine _objectivepgp_v3_policy_mappings BORINGSSL_PREFIX %+ __objectivepgp_v3_policy_mappings
%xdefine _objectivepgp_X509V3_EXT_print BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_print
%xdefine _objectivepgp_X509V3_EXT_print_fp BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_print_fp
%xdefine _objectivepgp_X509V3_EXT_val_prn BORINGSSL_PREFIX %+ __objectivepgp_X509V3_EXT_val_prn
%xdefine _objectivepgp_X509V3_extensions_print BORINGSSL_PREFIX %+ __objectivepgp_X509V3_extensions_print
%xdefine _objectivepgp_X509_PURPOSE_add BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_add
%xdefine _objectivepgp_X509_PURPOSE_cleanup BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_cleanup
%xdefine _objectivepgp_X509_PURPOSE_get0 BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0
%xdefine _objectivepgp_X509_PURPOSE_get0_name BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0_name
%xdefine _objectivepgp_X509_PURPOSE_get0_sname BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get0_sname
%xdefine _objectivepgp_X509_PURPOSE_get_by_id BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_by_id
%xdefine _objectivepgp_X509_PURPOSE_get_by_sname BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_by_sname
%xdefine _objectivepgp_X509_PURPOSE_get_count BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_count
%xdefine _objectivepgp_X509_PURPOSE_get_id BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_id
%xdefine _objectivepgp_X509_PURPOSE_get_trust BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_get_trust
%xdefine _objectivepgp_X509_PURPOSE_set BORINGSSL_PREFIX %+ __objectivepgp_X509_PURPOSE_set
%xdefine _objectivepgp_X509_check_akid BORINGSSL_PREFIX %+ __objectivepgp_X509_check_akid
%xdefine _objectivepgp_X509_check_ca BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ca
%xdefine _objectivepgp_X509_check_issued BORINGSSL_PREFIX %+ __objectivepgp_X509_check_issued
%xdefine _objectivepgp_X509_check_purpose BORINGSSL_PREFIX %+ __objectivepgp_X509_check_purpose
%xdefine _objectivepgp_X509_get_extended_key_usage BORINGSSL_PREFIX %+ __objectivepgp_X509_get_extended_key_usage
%xdefine _objectivepgp_X509_get_extension_flags BORINGSSL_PREFIX %+ __objectivepgp_X509_get_extension_flags
%xdefine _objectivepgp_X509_get_key_usage BORINGSSL_PREFIX %+ __objectivepgp_X509_get_key_usage
%xdefine _objectivepgp_X509_supported_extension BORINGSSL_PREFIX %+ __objectivepgp_X509_supported_extension
%xdefine _objectivepgp_i2s_ASN1_OCTET_STRING BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_OCTET_STRING
%xdefine _objectivepgp_s2i_ASN1_OCTET_STRING BORINGSSL_PREFIX %+ __objectivepgp_s2i_ASN1_OCTET_STRING
%xdefine _objectivepgp_v3_skey_id BORINGSSL_PREFIX %+ __objectivepgp_v3_skey_id
%xdefine _objectivepgp_SXNETID_free BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_free
%xdefine _objectivepgp_SXNETID_it BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_it
%xdefine _objectivepgp_SXNETID_new BORINGSSL_PREFIX %+ __objectivepgp_SXNETID_new
%xdefine _objectivepgp_SXNET_add_id_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_INTEGER
%xdefine _objectivepgp_SXNET_add_id_asc BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_asc
%xdefine _objectivepgp_SXNET_add_id_ulong BORINGSSL_PREFIX %+ __objectivepgp_SXNET_add_id_ulong
%xdefine _objectivepgp_SXNET_free BORINGSSL_PREFIX %+ __objectivepgp_SXNET_free
%xdefine _objectivepgp_SXNET_get_id_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_INTEGER
%xdefine _objectivepgp_SXNET_get_id_asc BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_asc
%xdefine _objectivepgp_SXNET_get_id_ulong BORINGSSL_PREFIX %+ __objectivepgp_SXNET_get_id_ulong
%xdefine _objectivepgp_SXNET_it BORINGSSL_PREFIX %+ __objectivepgp_SXNET_it
%xdefine _objectivepgp_SXNET_new BORINGSSL_PREFIX %+ __objectivepgp_SXNET_new
%xdefine _objectivepgp_d2i_SXNET BORINGSSL_PREFIX %+ __objectivepgp_d2i_SXNET
%xdefine _objectivepgp_d2i_SXNETID BORINGSSL_PREFIX %+ __objectivepgp_d2i_SXNETID
%xdefine _objectivepgp_i2d_SXNET BORINGSSL_PREFIX %+ __objectivepgp_i2d_SXNET
%xdefine _objectivepgp_i2d_SXNETID BORINGSSL_PREFIX %+ __objectivepgp_i2d_SXNETID
%xdefine _objectivepgp_v3_sxnet BORINGSSL_PREFIX %+ __objectivepgp_v3_sxnet
%xdefine _objectivepgp_X509V3_NAME_from_section BORINGSSL_PREFIX %+ __objectivepgp_X509V3_NAME_from_section
%xdefine _objectivepgp_X509V3_add_value BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value
%xdefine _objectivepgp_X509V3_add_value_bool BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_bool
%xdefine _objectivepgp_X509V3_add_value_bool_nf BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_bool_nf
%xdefine _objectivepgp_X509V3_add_value_int BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_int
%xdefine _objectivepgp_X509V3_add_value_uchar BORINGSSL_PREFIX %+ __objectivepgp_X509V3_add_value_uchar
%xdefine _objectivepgp_X509V3_conf_free BORINGSSL_PREFIX %+ __objectivepgp_X509V3_conf_free
%xdefine _objectivepgp_X509V3_get_value_bool BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_value_bool
%xdefine _objectivepgp_X509V3_get_value_int BORINGSSL_PREFIX %+ __objectivepgp_X509V3_get_value_int
%xdefine _objectivepgp_X509V3_parse_list BORINGSSL_PREFIX %+ __objectivepgp_X509V3_parse_list
%xdefine _objectivepgp_X509_REQ_get1_email BORINGSSL_PREFIX %+ __objectivepgp_X509_REQ_get1_email
%xdefine _objectivepgp_X509_check_email BORINGSSL_PREFIX %+ __objectivepgp_X509_check_email
%xdefine _objectivepgp_X509_check_host BORINGSSL_PREFIX %+ __objectivepgp_X509_check_host
%xdefine _objectivepgp_X509_check_ip BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ip
%xdefine _objectivepgp_X509_check_ip_asc BORINGSSL_PREFIX %+ __objectivepgp_X509_check_ip_asc
%xdefine _objectivepgp_X509_email_free BORINGSSL_PREFIX %+ __objectivepgp_X509_email_free
%xdefine _objectivepgp_X509_get1_email BORINGSSL_PREFIX %+ __objectivepgp_X509_get1_email
%xdefine _objectivepgp_X509_get1_ocsp BORINGSSL_PREFIX %+ __objectivepgp_X509_get1_ocsp
%xdefine _objectivepgp_a2i_IPADDRESS BORINGSSL_PREFIX %+ __objectivepgp_a2i_IPADDRESS
%xdefine _objectivepgp_a2i_IPADDRESS_NC BORINGSSL_PREFIX %+ __objectivepgp_a2i_IPADDRESS_NC
%xdefine _objectivepgp_a2i_ipadd BORINGSSL_PREFIX %+ __objectivepgp_a2i_ipadd
%xdefine _objectivepgp_i2s_ASN1_ENUMERATED BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_ENUMERATED
%xdefine _objectivepgp_i2s_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_i2s_ASN1_INTEGER
%xdefine _objectivepgp_s2i_ASN1_INTEGER BORINGSSL_PREFIX %+ __objectivepgp_s2i_ASN1_INTEGER
%xdefine _objectivepgp_x509v3_bytes_to_hex BORINGSSL_PREFIX %+ __objectivepgp_x509v3_bytes_to_hex
%xdefine _objectivepgp_x509v3_hex_to_bytes BORINGSSL_PREFIX %+ __objectivepgp_x509v3_hex_to_bytes
%xdefine _objectivepgp_x509v3_looks_like_dns_name BORINGSSL_PREFIX %+ __objectivepgp_x509v3_looks_like_dns_name
%xdefine _objectivepgp_x509v3_name_cmp BORINGSSL_PREFIX %+ __objectivepgp_x509v3_name_cmp
%xdefine _objectivepgp_ED25519_keypair BORINGSSL_PREFIX %+ __objectivepgp_ED25519_keypair
%xdefine _objectivepgp_ED25519_keypair_from_seed BORINGSSL_PREFIX %+ __objectivepgp_ED25519_keypair_from_seed
%xdefine _objectivepgp_ED25519_sign BORINGSSL_PREFIX %+ __objectivepgp_ED25519_sign
%xdefine _objectivepgp_ED25519_verify BORINGSSL_PREFIX %+ __objectivepgp_ED25519_verify
%xdefine _objectivepgp_X25519 BORINGSSL_PREFIX %+ __objectivepgp_X25519
%xdefine _objectivepgp_X25519_keypair BORINGSSL_PREFIX %+ __objectivepgp_X25519_keypair
%xdefine _objectivepgp_X25519_public_from_private BORINGSSL_PREFIX %+ __objectivepgp_X25519_public_from_private
%xdefine _objectivepgp_x25519_ge_add BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_add
%xdefine _objectivepgp_x25519_ge_frombytes_vartime BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_frombytes_vartime
%xdefine _objectivepgp_x25519_ge_p1p1_to_p2 BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p1p1_to_p2
%xdefine _objectivepgp_x25519_ge_p1p1_to_p3 BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p1p1_to_p3
%xdefine _objectivepgp_x25519_ge_p3_to_cached BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_p3_to_cached
%xdefine _objectivepgp_x25519_ge_scalarmult BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult
%xdefine _objectivepgp_x25519_ge_scalarmult_base BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult_base
%xdefine _objectivepgp_x25519_ge_scalarmult_small_precomp BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_scalarmult_small_precomp
%xdefine _objectivepgp_x25519_ge_sub BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_sub
%xdefine _objectivepgp_x25519_ge_tobytes BORINGSSL_PREFIX %+ __objectivepgp_x25519_ge_tobytes
%xdefine _objectivepgp_x25519_sc_reduce BORINGSSL_PREFIX %+ __objectivepgp_x25519_sc_reduce
%xdefine _objectivepgp_sike_fp2inv_mont BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2inv_mont
%xdefine _objectivepgp_sike_fp2mul_mont BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2mul_mont
%xdefine _objectivepgp_sike_fp2sqr_mont BORINGSSL_PREFIX %+ __objectivepgp_sike_fp2sqr_mont
%xdefine _objectivepgp_sike_fpcopy BORINGSSL_PREFIX %+ __objectivepgp_sike_fpcopy
%xdefine _objectivepgp_sike_fpcorrection BORINGSSL_PREFIX %+ __objectivepgp_sike_fpcorrection
%xdefine _objectivepgp_sike_fpdiv2 BORINGSSL_PREFIX %+ __objectivepgp_sike_fpdiv2
%xdefine _objectivepgp_sike_fpmul_mont BORINGSSL_PREFIX %+ __objectivepgp_sike_fpmul_mont
%xdefine _objectivepgp_sike_fpneg BORINGSSL_PREFIX %+ __objectivepgp_sike_fpneg
%xdefine _objectivepgp_sike_from_mont BORINGSSL_PREFIX %+ __objectivepgp_sike_from_mont
%xdefine _objectivepgp_sike_eval_3_isog BORINGSSL_PREFIX %+ __objectivepgp_sike_eval_3_isog
%xdefine _objectivepgp_sike_eval_4_isog BORINGSSL_PREFIX %+ __objectivepgp_sike_eval_4_isog
%xdefine _objectivepgp_sike_get_3_isog BORINGSSL_PREFIX %+ __objectivepgp_sike_get_3_isog
%xdefine _objectivepgp_sike_get_4_isog BORINGSSL_PREFIX %+ __objectivepgp_sike_get_4_isog
%xdefine _objectivepgp_sike_get_A BORINGSSL_PREFIX %+ __objectivepgp_sike_get_A
%xdefine _objectivepgp_sike_inv_3_way BORINGSSL_PREFIX %+ __objectivepgp_sike_inv_3_way
%xdefine _objectivepgp_sike_j_inv BORINGSSL_PREFIX %+ __objectivepgp_sike_j_inv
%xdefine _objectivepgp_sike_xDBLADD BORINGSSL_PREFIX %+ __objectivepgp_sike_xDBLADD
%xdefine _objectivepgp_sike_xDBLe BORINGSSL_PREFIX %+ __objectivepgp_sike_xDBLe
%xdefine _objectivepgp_sike_xTPL BORINGSSL_PREFIX %+ __objectivepgp_sike_xTPL
%xdefine _objectivepgp_sike_xTPLe BORINGSSL_PREFIX %+ __objectivepgp_sike_xTPLe
%xdefine _objectivepgp_sike_params BORINGSSL_PREFIX %+ __objectivepgp_sike_params
%xdefine _objectivepgp_SIKE_decaps BORINGSSL_PREFIX %+ __objectivepgp_SIKE_decaps
%xdefine _objectivepgp_SIKE_encaps BORINGSSL_PREFIX %+ __objectivepgp_SIKE_encaps
%xdefine _objectivepgp_SIKE_keypair BORINGSSL_PREFIX %+ __objectivepgp_SIKE_keypair
%xdefine _objectivepgp_ChaCha20_ctr32 BORINGSSL_PREFIX %+ __objectivepgp_ChaCha20_ctr32
%xdefine _objectivepgp_aes128gcmsiv_aes_ks BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_aes_ks
%xdefine _objectivepgp_aes128gcmsiv_aes_ks_enc_x1 BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_aes_ks_enc_x1
%xdefine _objectivepgp_aes128gcmsiv_dec BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_dec
%xdefine _objectivepgp_aes128gcmsiv_ecb_enc_block BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_ecb_enc_block
%xdefine _objectivepgp_aes128gcmsiv_enc_msg_x4 BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_enc_msg_x4
%xdefine _objectivepgp_aes128gcmsiv_enc_msg_x8 BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_enc_msg_x8
%xdefine _objectivepgp_aes128gcmsiv_kdf BORINGSSL_PREFIX %+ __objectivepgp_aes128gcmsiv_kdf
%xdefine _objectivepgp_aes256gcmsiv_aes_ks BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_aes_ks
%xdefine _objectivepgp_aes256gcmsiv_aes_ks_enc_x1 BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_aes_ks_enc_x1
%xdefine _objectivepgp_aes256gcmsiv_dec BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_dec
%xdefine _objectivepgp_aes256gcmsiv_ecb_enc_block BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_ecb_enc_block
%xdefine _objectivepgp_aes256gcmsiv_enc_msg_x4 BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_enc_msg_x4
%xdefine _objectivepgp_aes256gcmsiv_enc_msg_x8 BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_enc_msg_x8
%xdefine _objectivepgp_aes256gcmsiv_kdf BORINGSSL_PREFIX %+ __objectivepgp_aes256gcmsiv_kdf
%xdefine _objectivepgp_aesgcmsiv_htable6_init BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable6_init
%xdefine _objectivepgp_aesgcmsiv_htable_init BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable_init
%xdefine _objectivepgp_aesgcmsiv_htable_polyval BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_htable_polyval
%xdefine _objectivepgp_aesgcmsiv_polyval_horner BORINGSSL_PREFIX %+ __objectivepgp_aesgcmsiv_polyval_horner
%xdefine _objectivepgp_chacha20_poly1305_open BORINGSSL_PREFIX %+ __objectivepgp_chacha20_poly1305_open
%xdefine _objectivepgp_chacha20_poly1305_seal BORINGSSL_PREFIX %+ __objectivepgp_chacha20_poly1305_seal
%xdefine _objectivepgp_abi_test_bad_unwind_temporary BORINGSSL_PREFIX %+ __objectivepgp_abi_test_bad_unwind_temporary
%xdefine _objectivepgp_abi_test_bad_unwind_wrong_register BORINGSSL_PREFIX %+ __objectivepgp_abi_test_bad_unwind_wrong_register
%xdefine _objectivepgp_abi_test_clobber_r10 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r10
%xdefine _objectivepgp_abi_test_clobber_r11 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r11
%xdefine _objectivepgp_abi_test_clobber_r12 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r12
%xdefine _objectivepgp_abi_test_clobber_r13 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r13
%xdefine _objectivepgp_abi_test_clobber_r14 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r14
%xdefine _objectivepgp_abi_test_clobber_r15 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r15
%xdefine _objectivepgp_abi_test_clobber_r8 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r8
%xdefine _objectivepgp_abi_test_clobber_r9 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_r9
%xdefine _objectivepgp_abi_test_clobber_rax BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rax
%xdefine _objectivepgp_abi_test_clobber_rbp BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rbp
%xdefine _objectivepgp_abi_test_clobber_rbx BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rbx
%xdefine _objectivepgp_abi_test_clobber_rcx BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rcx
%xdefine _objectivepgp_abi_test_clobber_rdi BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rdi
%xdefine _objectivepgp_abi_test_clobber_rdx BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rdx
%xdefine _objectivepgp_abi_test_clobber_rsi BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_rsi
%xdefine _objectivepgp_abi_test_clobber_xmm0 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm0
%xdefine _objectivepgp_abi_test_clobber_xmm1 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm1
%xdefine _objectivepgp_abi_test_clobber_xmm10 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm10
%xdefine _objectivepgp_abi_test_clobber_xmm11 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm11
%xdefine _objectivepgp_abi_test_clobber_xmm12 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm12
%xdefine _objectivepgp_abi_test_clobber_xmm13 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm13
%xdefine _objectivepgp_abi_test_clobber_xmm14 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm14
%xdefine _objectivepgp_abi_test_clobber_xmm15 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm15
%xdefine _objectivepgp_abi_test_clobber_xmm2 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm2
%xdefine _objectivepgp_abi_test_clobber_xmm3 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm3
%xdefine _objectivepgp_abi_test_clobber_xmm4 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm4
%xdefine _objectivepgp_abi_test_clobber_xmm5 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm5
%xdefine _objectivepgp_abi_test_clobber_xmm6 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm6
%xdefine _objectivepgp_abi_test_clobber_xmm7 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm7
%xdefine _objectivepgp_abi_test_clobber_xmm8 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm8
%xdefine _objectivepgp_abi_test_clobber_xmm9 BORINGSSL_PREFIX %+ __objectivepgp_abi_test_clobber_xmm9
%xdefine _objectivepgp_abi_test_get_and_clear_direction_flag BORINGSSL_PREFIX %+ __objectivepgp_abi_test_get_and_clear_direction_flag
%xdefine _objectivepgp_abi_test_set_direction_flag BORINGSSL_PREFIX %+ __objectivepgp_abi_test_set_direction_flag
%xdefine _objectivepgp_abi_test_trampoline BORINGSSL_PREFIX %+ __objectivepgp_abi_test_trampoline
%xdefine _objectivepgp_abi_test_unwind_return BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_return
%xdefine _objectivepgp_abi_test_unwind_start BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_start
%xdefine _objectivepgp_abi_test_unwind_stop BORINGSSL_PREFIX %+ __objectivepgp_abi_test_unwind_stop
%xdefine _objectivepgp_sike_cswap_asm BORINGSSL_PREFIX %+ __objectivepgp_sike_cswap_asm
%xdefine _objectivepgp_sike_fpadd BORINGSSL_PREFIX %+ __objectivepgp_sike_fpadd
%xdefine _objectivepgp_sike_fprdc BORINGSSL_PREFIX %+ __objectivepgp_sike_fprdc
%xdefine _objectivepgp_sike_fpsub BORINGSSL_PREFIX %+ __objectivepgp_sike_fpsub
%xdefine _objectivepgp_sike_mpadd_asm BORINGSSL_PREFIX %+ __objectivepgp_sike_mpadd_asm
%xdefine _objectivepgp_sike_mpdblsubx2_asm BORINGSSL_PREFIX %+ __objectivepgp_sike_mpdblsubx2_asm
%xdefine _objectivepgp_sike_mpmul BORINGSSL_PREFIX %+ __objectivepgp_sike_mpmul
%xdefine _objectivepgp_sike_mpsubx2_asm BORINGSSL_PREFIX %+ __objectivepgp_sike_mpsubx2_asm
%endif
