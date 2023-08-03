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
+ (BOOL)verify:(NSData *)hash signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket{
    return [self verify:hash signature:signaturePacket withPublicKeyPacket:publicKeyPacket error:nil];
}

+ (BOOL)verify:(NSData *)hash signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket error:(NSError * __autoreleasing _Nullable * _Nullable)error{
    if (error) * error = nil;
    
    let sig = DSA_SIG_new();
    if (!sig) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: @"Could not initialize DSA Signature" }];
        }
        return NO;
    }
    // setup DSA Signature
    let r = BN_dup([[[signaturePacket signatureMPI:PGPMPIdentifierR] bigNum] bignumRef]);
    let s = BN_dup([[[signaturePacket signatureMPI:PGPMPIdentifierS] bigNum] bignumRef]);
    
    if (!r || !s) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: @"Missing DSA Signature values" }];
        }
        PGPLogError(@"Missing DSA Signature values. r=%p, s=%p",r,s);
        return NO;
    }
    
    DSA_SIG_set0(sig, r, s);
    
    
    pgp_defer { DSA_SIG_free(sig); };
    
    let dsa = DSA_new();
    if (!dsa) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: @"Could not initialize DSA Hash Validation" }];
        }
        return NO;
    }
    pgp_defer { DSA_free(dsa); };

   
    
    // set up DSA pgq
    let p = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierP] bigNum] bignumRef]);
    let q = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierQ] bigNum] bignumRef]);
    let g = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierG] bigNum] bignumRef]);
    
    if (!p || !q || !g ) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: @"Missing DSA PGQ values" }];
        }
        PGPLogError(@"Missing DSA values. p=%p, q=%p, g=%p",p,q,g);
        return NO;
    }
    DSA_set0_pqg(dsa, p, q, g);
   
    // set up DSA pgq
    let pub_key = BN_dup([[[publicKeyPacket publicMPI:PGPMPIdentifierY] bigNum] bignumRef]);
    
    if (!pub_key) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: @"Missing DSA Y value" }];
        }
        PGPLogError(@"Missing DSA values. y=%p",pub_key);
        return NO;
    }
    DSA_set0_key(dsa, pub_key, NULL);
   
    
    var hashLen = (unsigned int)hash.length;
    unsigned int qlen = 0;
    if ((qlen = (unsigned int)BN_num_bytes(DSA_get0_q(dsa))) < hashLen) {
        hashLen = qlen;
    }

    let ret = DSA_do_verify(hash.bytes, hashLen, sig, dsa);
    PGPLogError(@"DSA_do_verify result. %d",ret);
   
    if (ret < 0) {
       // #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        let errorString = [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding];
        PGPLogDebug(@"%@", errorString);
      //  #endif
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorSignatureVerificationFailure userInfo:@{ NSLocalizedDescriptionKey: errorString?:@"Could not validate signing key" }];
        }
        return NO;
    }

    if (ret == 1) {
        return YES;
    }

    if (error) {
        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Invalid signature" }];
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
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
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
