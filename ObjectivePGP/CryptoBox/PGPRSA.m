//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPRSA.h"
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
#import <openssl/rsa.h>

#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPRSA

// encrypts the bytes
+ (nullable NSData *)publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    let n = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    let e = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);
    if (!n || !e) {
        return nil;
    }

    let rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };
    RSA_set0_key(rsa, n, e, NULL);

    uint8_t *encrypted_em = calloc((size_t)BN_num_bytes(n) & SIZE_T_MAX, 1);
    pgp_defer { free(encrypted_em); };

    int em_len = RSA_public_encrypt(toEncrypt.length & INT_MAX, toEncrypt.bytes, encrypted_em, rsa, RSA_NO_PADDING);
    if (em_len == -1 || em_len != (publicKeyPacket.keySize & INT_MAX)) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

     // encrypted encoded EME
     let encryptedEm = [NSData dataWithBytes:encrypted_em length:em_len];
     return encryptedEm;
}

// decrypt bytes
+ (nullable NSData *)privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket {
    let rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    let n = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    let e = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    let d = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_D] bigNum] bignumRef]);
    let p = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_Q] bigNum] bignumRef]); /* p and q are round the other way in openssl */
    let q = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_P] bigNum] bignumRef]);

    if (d == NULL) {
        return nil;
    }

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);

    if (RSA_check_key(rsa) != 1) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

    uint8_t *outbuf = calloc(RSA_size(rsa) & SIZE_T_MAX, 1);
    pgp_defer { free(outbuf); };
    int t = RSA_private_decrypt(toDecrypt.length & INT_MAX, toDecrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t == -1) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

    NSData *decryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(decryptedData, @"Missing data");
    return decryptedData;
}

// sign
+ (nullable NSData *)privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket {
    let rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    let n = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    let e = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);
    let d = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_D] bigNum] bignumRef]);
    let p = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_Q] bigNum] bignumRef]); /* p and q are round the other way in openssl */
    let q = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_P] bigNum] bignumRef]);

    if (toEncrypt.length > secretKeyPacket.keySize) {
        return nil;
    }

    /* If this isn't set, it's very likely that the programmer hasn't */
    /* decrypted the secret key. RSA_check_key segfaults in that case. */
    if (d == NULL) {
        return nil;
    }

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);

    if (RSA_check_key(rsa) != 1) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

    uint8_t *outbuf = calloc(RSA_size(rsa) & SIZE_T_MAX, 1);
    pgp_defer { free(outbuf); };

    int t = RSA_private_encrypt(toEncrypt.length & INT_MAX, (UInt8 *)toEncrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t == -1) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

    NSData *encryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(encryptedData, @"Missing calculated data");
    return encryptedData;
}

// recovers the message digest
+ (nullable NSData *)publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    let rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    let n = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    let e = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    if (!n || !e) {
        return nil;
    }

    RSA_set0_key(rsa, n, e, NULL);

    uint8_t *decrypted_em = calloc(RSA_size(rsa) & SIZE_T_MAX, 1); // RSA_size(rsa) - 11
    pgp_defer { free(decrypted_em); };
    int em_len = RSA_public_decrypt(toDecrypt.length & INT_MAX, toDecrypt.bytes, decrypted_em, rsa, RSA_NO_PADDING);
    if (em_len == -1 || em_len != (publicKeyPacket.keySize & INT_MAX)) {
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        return nil;
    }

    // decrypted PKCS emsa
    let decryptedEm = [NSData dataWithBytes:decrypted_em length:em_len];
    return decryptedEm;
}

#pragma mark - Generate

+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits {
    BN_CTX *ctx = BN_CTX_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    pgp_defer {
        BN_CTX_free(ctx);
        BN_clear_free(e);
        RSA_free(rsa);
    };

    BN_set_word(e, 65537UL);

    if (RSA_generate_key_ex(rsa, bits, e, NULL) != 1) {
        return nil;
    }

    RSA_get0_n(rsa);

    let bigN = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(RSA_get0_n(rsa))];
    let bigE = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(RSA_get0_e(rsa))];
    let bigD = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(RSA_get0_d(rsa))];
    let bigP = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(RSA_get0_p(rsa))];
    let bigQ = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(RSA_get0_q(rsa))];
    let bigU = [[PGPBigNum alloc] initWithBIGNUM:BN_mod_inverse(NULL, RSA_get0_p(rsa), RSA_get0_q(rsa), ctx)];

    let mpiN = [[PGPMPI alloc] initWithBigNum:bigN identifier:PGPMPI_N];
    let mpiE = [[PGPMPI alloc] initWithBigNum:bigE identifier:PGPMPI_E];
    let mpiD = [[PGPMPI alloc] initWithBigNum:bigD identifier:PGPMPI_D];
    let mpiP = [[PGPMPI alloc] initWithBigNum:bigP identifier:PGPMPI_P];
    let mpiQ = [[PGPMPI alloc] initWithBigNum:bigQ identifier:PGPMPI_Q];
    let mpiU = [[PGPMPI alloc] initWithBigNum:bigU identifier:PGPMPI_U];

    let keyMaterial = [[PGPKeyMaterial alloc] init];
    keyMaterial.n = mpiN;
    keyMaterial.e = mpiE;
    keyMaterial.d = mpiD;
    keyMaterial.p = mpiP;
    keyMaterial.q = mpiQ;
    keyMaterial.u = mpiU;

    return keyMaterial;
}

@end

NS_ASSUME_NONNULL_END
