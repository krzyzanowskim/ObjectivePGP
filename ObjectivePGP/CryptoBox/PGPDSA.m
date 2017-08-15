//
//  PGPDSA.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPDSA.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPBigNum+Private.h"

#import "PGPLogging.h"
#import "PGPMacros.h"

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>
#import <openssl/dsa.h>
#import <openssl/ecdsa.h>

#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPDSA

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    DSA_SIG *sig = DSA_SIG_new();
    pgp_defer { if (sig) { DSA_SIG_free(sig); } };
    
    DSA *dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    if (!dsa || !sig) {
        return NO;
    }

    dsa->p = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_P] bigNum] bignumRef]);
    dsa->q = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_Q] bigNum] bignumRef]);
    dsa->g = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_G] bigNum] bignumRef]);
    dsa->pub_key = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_Y] bigNum] bignumRef]);

    sig->r = BN_dup([[[signaturePacket signatureMPI:PGPMPI_R] bigNum] bignumRef]);
    sig->s = BN_dup([[[signaturePacket signatureMPI:PGPMPI_S] bigNum] bignumRef]);

    if (!dsa->p || !dsa->q || !dsa->g || !dsa->pub_key || sig->r || sig->s) {
        PGPLogError(@"Missing DSA values.");
        return NO;
    }

    var hashLen = toVerify.length;
    unsigned int qlen = 0;
    if ((qlen = (unsigned int)BN_num_bytes(dsa->q)) < hashLen) {
        hashLen = qlen;
    }

    if (DSA_do_verify(toVerify.bytes, (int)hashLen, sig, dsa) < 0) {
        ERR_load_crypto_strings();
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        pgp_defer { if (errBuf) { free(errBuf); } };
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        return NO;
    }

    dsa->p = dsa->q = dsa->g = dsa->pub_key = NULL;
    sig->r = sig->s = NULL;
    return YES;
}

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key {
    DSA *dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    if (!dsa) {
        return @[];
    }

    let signingKeyPacket = key.signingSecretKey;
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    dsa->p = BN_dup([publicKeyPacket publicMPI:PGPMPI_P].bigNum.bignumRef);
    dsa->q = BN_dup([publicKeyPacket publicMPI:PGPMPI_Q].bigNum.bignumRef);
    dsa->g = BN_dup([publicKeyPacket publicMPI:PGPMPI_G].bigNum.bignumRef);
    dsa->pub_key = BN_dup([publicKeyPacket publicMPI:PGPMPI_Y].bigNum.bignumRef);
    dsa->priv_key = BN_dup([signingKeyPacket secretMPI:PGPMPI_X].bigNum.bignumRef);

    DSA_SIG * _Nullable sig = DSA_do_sign(toSign.bytes, (int)toSign.length, dsa);
    if (!sig) {
        ERR_load_crypto_strings();
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        pgp_defer { if (errBuf) { free(errBuf); } };
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
    }

    let MPI_R = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:sig->r] identifier:PGPMPI_R];
    let MPI_S = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:sig->s] identifier:PGPMPI_S];

    dsa->p = dsa->q = dsa->g = dsa->pub_key = dsa->priv_key = NULL;

    return @[MPI_R, MPI_S];
}


#pragma mark - Generate

+ (nullable NSSet<PGPMPI *> *)generateNewKeyMPIs:(const int)bits algorithm:(PGPPublicKeyAlgorithm)algorithm {    
    BN_CTX *ctx = BN_CTX_new();
    pgp_defer { if (ctx) { BN_CTX_free(ctx); } };
    DSA *dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL);
    if (DSA_generate_key(dsa) != 1) {
        return nil;
    }

    let bigP = [[PGPBigNum alloc] initWithBIGNUM:dsa->p];
    let bigQ = [[PGPBigNum alloc] initWithBIGNUM:dsa->q];
    let bigG = [[PGPBigNum alloc] initWithBIGNUM:dsa->g];
    let bigR = [[PGPBigNum alloc] initWithBIGNUM:dsa->r];
    let bigX = [[PGPBigNum alloc] initWithBIGNUM:dsa->priv_key];
    let bigY = [[PGPBigNum alloc] initWithBIGNUM:dsa->pub_key];

    let mpiP = [[PGPMPI alloc] initWithBigNum:bigP identifier:PGPMPI_P];
    let mpiQ = [[PGPMPI alloc] initWithBigNum:bigQ identifier:PGPMPI_Q];
    let mpiG = [[PGPMPI alloc] initWithBigNum:bigG identifier:PGPMPI_G];
    let mpiR = [[PGPMPI alloc] initWithBigNum:bigR identifier:PGPMPI_R];
    let mpiX = [[PGPMPI alloc] initWithBigNum:bigX identifier:PGPMPI_X];
    let mpiY = [[PGPMPI alloc] initWithBigNum:bigY identifier:PGPMPI_Y];

    return [NSSet setWithArray:@[mpiP, mpiQ, mpiG, mpiR, mpiY, mpiX]];
}

@end

NS_ASSUME_NONNULL_END
