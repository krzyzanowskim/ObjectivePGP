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
    let p = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierP] bigNum] bignumRef]);
    let g = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierG] bigNum] bignumRef]);
    let y = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierY] bigNum] bignumRef]);

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
    BN_clear_free(p);
    BN_clear_free(y);
    BN_clear_free(m);

    return @[g_k, encm];
}

+ (nullable NSData *)privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket gk:(PGPMPI *)gkMPI {
    let c2 = BN_bin2bn(toDecrypt.bytes, toDecrypt.length & INT_MAX, NULL);
    let c1 = BN_dup([[gkMPI bigNum] bignumRef]);
    let p = BN_dup([[[secretKeyPacket publicMPI:PGPMPIdentifierP] bigNum] bignumRef]);
    let x = BN_dup([[[secretKeyPacket secretMPI:PGPMPIdentifierX] bigNum] bignumRef]);


    let c1x = BN_new();
    let bndiv = BN_new();
    let m = BN_new();
    let tmp = BN_CTX_new();

    BN_mod_exp(c1x, c1, x, p, tmp);
    BN_mod_inverse(bndiv, c1x, p, tmp);
    BN_mod_mul(m, c2, bndiv, p, tmp);

    let decm = [[PGPBigNum alloc] initWithBIGNUM:m];

    BN_CTX_free(tmp);
    BN_clear_free(c1x);
    BN_clear_free(bndiv);
    BN_clear_free(m);
    BN_clear_free(p);
    BN_clear_free(x);
    BN_clear_free(c1);
    BN_clear_free(c2);

    return [decm data];
}


@end

NS_ASSUME_NONNULL_END
