//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPElgamal.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPBigNum+Private.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPElgamal

static int decide_k_bits(int p_bits) {
    return (p_bits <= 5120) ? p_bits / 10 + 160 : (p_bits / 8 + 200) * 3 / 2;
}

// encrypt the bytes, returns encrypted m
+ (nullable NSArray<PGPBigNum *> *)publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    let m = BN_bin2bn(toEncrypt.bytes, toEncrypt.length & INT_MAX, NULL);
    let p = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_P] bigNum] bignumRef]);
    let g = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_G] bigNum] bignumRef]);
    let y = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_Y] bigNum] bignumRef]);

    let k = BN_new();
    let yk = BN_new();
    let c1 = BN_new();
    let c2 = BN_new();
    let tmp = BN_CTX_new();

    // k
    let k_bits = decide_k_bits(BN_num_bits(p));
    BN_rand(k, k_bits, 0, 0);

    // c1 = g^k c2 = m * y^k
    BN_mod_exp(c1, g, k, p, tmp);
    BN_mod_exp(yk, y, k, p, tmp);
    BN_mod_mul(c2, m, yk, p, tmp);

    // c1 = g^k
    // c2 = m * y^k
    let g_k = [[PGPBigNum alloc] initWithBIGNUM:c1];
    let encm = [[PGPBigNum alloc] initWithBIGNUM:c2];

    BN_CTX_free(tmp);
    BN_clear_free(c2);
    BN_clear_free(c1);
    BN_clear_free(yk);
    BN_clear_free(k);
    BN_clear_free(g);

    return @[g_k, encm];
}

@end

NS_ASSUME_NONNULL_END
