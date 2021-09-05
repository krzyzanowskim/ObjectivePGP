//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPDSA.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPBigNum+Private.h"
#import "PGPKey.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>
#import <openssl/dsa.h>
#import <openssl/ecdsa.h>

#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPDSA

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    let sig = DSA_SIG_new();
    if (!sig) {
        return NO;
    }
    pgp_defer { DSA_SIG_free(sig); };
    
    let dsa = DSA_new();
    if (!dsa) {
        return NO;
    }
    pgp_defer { DSA_free(dsa); };

    let p = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierP] bigNum] bignumRef]);
    let q = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierQ] bigNum] bignumRef]);
    let g = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierG] bigNum] bignumRef]);
    let pub_key = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierY] bigNum] bignumRef]);

    DSA_set0_pqg(dsa, p, q, g);
    DSA_set0_key(dsa, pub_key, NULL);

    let r = BN_dup([[[signaturePacket signatureMPI:PGPMPIdentifierR] bigNum] bignumRef]);
    let s = BN_dup([[[signaturePacket signatureMPI:PGPMPIdentifierS] bigNum] bignumRef]);

    DSA_SIG_set0(sig, r, s);

    if (!p || !q || !g || !pub_key || r || s) {
        PGPLogError(@"Missing DSA values.");
        return NO;
    }

    var hashLen = toVerify.length;
    unsigned int qlen = 0;
    if ((qlen = (unsigned int)BN_num_bytes(DSA_get0_q(dsa))) < hashLen) {
        hashLen = qlen;
    }

    let ret = DSA_do_verify(toVerify.bytes, (int)hashLen, sig, dsa);
    if (ret < 0) {
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
        return NO;
    }

    if (ret == 1) {
        return YES;
    }

    return NO;
}

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key {
    let dsa = DSA_new();
    if (!dsa) {
        return @[];
    }
    pgp_defer {
        DSA_free(dsa);
    };

    let signingKeyPacket = key.signingSecretKey;
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    let p = BN_dup([publicKeyPacket publicMPI:PGPMPIdentifierP].bigNum.bignumRef);
    let q = BN_dup([publicKeyPacket publicMPI:PGPMPIdentifierQ].bigNum.bignumRef);
    let g = BN_dup([publicKeyPacket publicMPI:PGPMPIdentifierG].bigNum.bignumRef);
    let pub_key = BN_dup([publicKeyPacket publicMPI:PGPMPIdentifierY].bigNum.bignumRef);
    let priv_key = BN_dup([signingKeyPacket secretMPI:PGPMPIdentifierX].bigNum.bignumRef);

    DSA_set0_pqg(dsa, p, q, g);
    DSA_set0_key(dsa, pub_key, priv_key);

    DSA_SIG * _Nullable sig = DSA_do_sign(toSign.bytes, (int)toSign.length, dsa);
    if (!sig) {
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
        return @[];
    }

    const BIGNUM *r;
    const BIGNUM *s;
    DSA_SIG_get0(sig, &r, &s);
    let MPI_R = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:BN_dup(r)] identifier:PGPMPIdentifierR];
    let MPI_S = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:BN_dup(s)] identifier:PGPMPIdentifierS];

    return @[MPI_R, MPI_S];
}


#pragma mark - Generate

+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits {    
    let ctx = BN_CTX_secure_new();
    pgp_defer { if (ctx) { BN_CTX_free(ctx); } };
    let dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL);
    if (DSA_generate_key(dsa) != 1) {
        return nil;
    }

    const BIGNUM *pub_key;
    const BIGNUM *priv_key;
    DSA_get0_key(dsa, &pub_key, &priv_key);
    let bigP = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_p(dsa))];
    let bigQ = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_q(dsa))];
    let bigG = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_g(dsa))];
    // let bigR = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_r(dsa))];
    let bigX = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(priv_key)];
    let bigY = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(pub_key)];

    let mpiP = [[PGPMPI alloc] initWithBigNum:bigP identifier:PGPMPIdentifierP];
    let mpiQ = [[PGPMPI alloc] initWithBigNum:bigQ identifier:PGPMPIdentifierQ];
    let mpiG = [[PGPMPI alloc] initWithBigNum:bigG identifier:PGPMPIdentifierG];
    // let mpiR = [[PGPMPI alloc] initWithBigNum:bigR identifier:PGPMPIdentifierR];
    let mpiX = [[PGPMPI alloc] initWithBigNum:bigX identifier:PGPMPIdentifierX];
    let mpiY = [[PGPMPI alloc] initWithBigNum:bigY identifier:PGPMPIdentifierY];

    let keyMaterial = [[PGPKeyMaterial alloc] init];
    keyMaterial.p = mpiP;
    keyMaterial.q = mpiQ;
    keyMaterial.g = mpiG;
    // keyMaterial.r = mpiR;
    keyMaterial.x = mpiX;
    keyMaterial.y = mpiY;

    return keyMaterial;
}

@end

NS_ASSUME_NONNULL_END
