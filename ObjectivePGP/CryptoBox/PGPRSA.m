//
//  PGPRSA.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPRSA.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPBigNum+Private.h"

#import "PGPLogging.h"
#import "PGPMacros.h"

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>
#import <openssl/rsa.h>

#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPRSA

// encrypts the bytes
+ (nullable NSData *)publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    rsa->n = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    rsa->e = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    NSAssert(rsa->n && rsa->e, @"Missing N or E");
    if (!rsa->n || !rsa->e) {
        return nil;
    }

    uint8_t *encrypted_em = calloc(BN_num_bytes(rsa->n) & SIZE_T_MAX, 1);
    pgp_defer { free(encrypted_em); };
    int em_len = RSA_public_encrypt(toEncrypt.length & INT_MAX, toEncrypt.bytes, encrypted_em, rsa, RSA_NO_PADDING);
    if (em_len == -1 || em_len != (publicKeyPacket.keySize & INT_MAX)) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);
        return nil;
    }

    // decrypted encoded EME
    NSData *encryptedEm = [NSData dataWithBytes:encrypted_em length:em_len];

    rsa->n = rsa->e = NULL;
    return encryptedEm;
}

// decrypt bytes
+ (nullable NSData *)privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket {
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    rsa->n = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    rsa->e = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    rsa->d = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_D] bigNum] bignumRef]);
    rsa->p = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_Q] bigNum] bignumRef]); /* p and q are round the other way in openssl */
    rsa->q = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_P] bigNum] bignumRef]);

    if (rsa->d == NULL) {
        return nil;
    }

    if (RSA_check_key(rsa) != 1) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        return nil;
    }

    uint8_t *outbuf = calloc(RSA_size(rsa) & SIZE_T_MAX, 1);
    pgp_defer { free(outbuf); };
    int t = RSA_private_decrypt(toDecrypt.length & INT_MAX, toDecrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t == -1) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        return nil;
    }

    NSData *decryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(decryptedData, @"Missing data");

    rsa->n = rsa->d = rsa->p = rsa->q = rsa->e = NULL;

    return decryptedData;
}

// sign
+ (nullable NSData *)privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket {
    let rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    rsa->n = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    rsa->d = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_D] bigNum] bignumRef]);
    rsa->p = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_Q] bigNum] bignumRef]); /* p and q are round the other way in openssl */
    rsa->q = BN_dup([[[secretKeyPacket secretMPI:PGPMPI_P] bigNum] bignumRef]);
    rsa->e = BN_dup([[[secretKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    if (toEncrypt.length > secretKeyPacket.keySize) {
        return nil;
    }

    /* If this isn't set, it's very likely that the programmer hasn't */
    /* decrypted the secret key. RSA_check_key segfaults in that case. */
    if (rsa->d == NULL) {
        return nil;
    }

    if (RSA_check_key(rsa) != 1) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        return nil;
    }

    uint8_t *outbuf = calloc(RSA_size(rsa) & SIZE_T_MAX, 1);
    pgp_defer { free(outbuf); };

    int t = RSA_private_encrypt(toEncrypt.length & INT_MAX, (UInt8 *)toEncrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t == -1) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        return nil;
    }

    NSData *encryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(encryptedData, @"Missing calculated data");

    rsa->n = rsa->d = rsa->p = rsa->q = rsa->e = NULL;

    return encryptedData;
}

// recovers the message digest
+ (nullable NSData *)publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    pgp_defer { RSA_free(rsa); };

    rsa->n = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_N] bigNum] bignumRef]);
    rsa->e = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_E] bigNum] bignumRef]);

    NSAssert(rsa->n && rsa->e, @"Missing N or E");
    if (!rsa->n || !rsa->e) {
        return nil;
    }

    uint8_t *decrypted_em = calloc(RSA_size(rsa) & SIZE_T_MAX, 1); // RSA_size(rsa) - 11
    pgp_defer { free(decrypted_em); };
    int em_len = RSA_public_decrypt(toDecrypt.length & INT_MAX, toDecrypt.bytes, decrypted_em, rsa, RSA_NO_PADDING);
    if (em_len == -1 || em_len != (publicKeyPacket.keySize & INT_MAX)) {
        ERR_load_crypto_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        return nil;
    }

    // decrypted PKCS emsa
    NSData *decryptedEm = [NSData dataWithBytes:decrypted_em length:em_len];

    rsa->n = rsa->e = NULL;

    return decryptedEm;
}

#pragma mark - Generate

+ (nullable NSSet<PGPMPI *> *)generateNewKeyMPIs:(const int)bits algorithm:(PGPPublicKeyAlgorithm)algorithm {    
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

    let bigN = [[PGPBigNum alloc] initWithBIGNUM:rsa->n];
    let bigE = [[PGPBigNum alloc] initWithBIGNUM:rsa->e];
    let bigD = [[PGPBigNum alloc] initWithBIGNUM:rsa->d];
    let bigP = [[PGPBigNum alloc] initWithBIGNUM:rsa->p];
    let bigQ = [[PGPBigNum alloc] initWithBIGNUM:rsa->q];
    let bigU = [[PGPBigNum alloc] initWithBIGNUM:BN_mod_inverse(NULL, rsa->p, rsa->q, ctx)];

    let mpiN = [[PGPMPI alloc] initWithBigNum:bigN identifier:PGPMPI_N];
    let mpiE = [[PGPMPI alloc] initWithBigNum:bigE identifier:PGPMPI_E];
    let mpiD = [[PGPMPI alloc] initWithBigNum:bigD identifier:PGPMPI_D];
    let mpiP = [[PGPMPI alloc] initWithBigNum:bigP identifier:PGPMPI_P];
    let mpiQ = [[PGPMPI alloc] initWithBigNum:bigQ identifier:PGPMPI_Q];
    let mpiU = [[PGPMPI alloc] initWithBigNum:bigU identifier:PGPMPI_U];

    return [NSSet setWithArray:@[mpiN, mpiE, mpiD, mpiP, mpiQ, mpiU]];

//#if FALSE
//    // Due to SecKeyCopyExternalRepresentation can't use Security for target < iOS 10
//    // TODO: use conditionaly with @available(ios 10.10, *) after Xcode 9 release.
//    let parameters = @{
//         (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
//         (id)kSecAttrKeySizeInBits: @(bits),
//         (id)kSecPrivateKeyAttrs:   @{
//                 (id)kSecAttrIsPermanent:    @NO,
//                 (id)kSecAttrIsSensitive:    @YES,
//                 (id)kSecAttrLabel: @"com.krzyzanowskim.objectivepgp.private"
//             },
//    };
//
//    CFErrorRef error = NULL;
//    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)parameters, &error);
//    if (!privateKey) {
//        NSError *err = CFBridgingRelease(error);
//        PGPLogError(@"%@",err);
//        return nil;
//    }
//
//    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
//
//    if (publicKey)  {
//        CFRelease(publicKey);
//    }
//
//    CFErrorRef exportError = NULL;
//    let privateKeyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &exportError));
//    if (!privateKeyData) {
//        NSError *err = CFBridgingRelease(error);
//        PGPLogError(@"%@",err);
//        CFRelease(privateKey);
//        return nil;
//    }
//
//    if (privateKey) {
//        CFRelease(privateKey);
//    }
//
//    if (publicKey) {
//        CFRelease(publicKey);
//    }
//
//    return privateKeyData;
//#endif
}

@end

NS_ASSUME_NONNULL_END
