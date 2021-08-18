//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPEC.h"
#import "PGPMPI.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPPublicKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPKey.h"
#import "PGPBigNum+Private.h"
#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

#import <openssl/err.h>
#import <openssl/ssl.h>
#import <openssl/evp.h>
#import <openssl/ec.h>
#import <openssl/ecdh.h>
#import <openssl/ecdsa.h>

#import <openssl/bn.h>
#import <openssl/rsa.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPEC

/// Generate ECDHE secret from private key and public part of ephemeral key
+ (nullable NSData *)generatePrivateEphemeralKeyWith:(NSData *)publicPartEphemeralKey curveKind:(PGPCurve)curveKind privateKey:(NSData *)privateKeyData {
    switch (curveKind) {
        case PGPCurveP256:
        case PGPCurveP384:
        case PGPCurveP521:
        case PGPCurveBrainpoolP256r1:
        case PGPCurveBrainpoolP512r1:
            // TODO: Implement missing curves?
            return nil;
        case PGPCurveEd25519: {
            NSAssert(NO, @"Curve %@ support not implemented.", @(curveKind));
            return nil;
        } break;
        case PGPCurve25519: {
            // secret_key = reverse D bytes
            let secret_key = [privateKeyData pgp_reversed];
            let pkey_private_key_D = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key.bytes, secret_key.length);
            if (!pkey_private_key_D) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                EVP_PKEY_free(pkey_private_key_D);
            };

            let V = [publicPartEphemeralKey subdataWithRange:NSMakeRange(1, publicPartEphemeralKey.length - 1)]; // public key
            let pkey_public_key_V = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, V.bytes , V.length);
            if (!pkey_public_key_V) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                EVP_PKEY_free(pkey_public_key_V);
            };

            // Compute the shared point S = vR;
            size_t derived_keylen = 32;
            let shared_key = OPENSSL_secure_malloc(derived_keylen);
            let ctx = EVP_PKEY_CTX_new(pkey_private_key_D, NULL);
            pgp_defer {
                OPENSSL_secure_clear_free(shared_key, derived_keylen);
                EVP_PKEY_CTX_free(ctx);
            };
            
            if (!ctx || EVP_PKEY_derive_init(ctx) <= 0
                || EVP_PKEY_derive_set_peer(ctx, pkey_public_key_V) <= 0
                || EVP_PKEY_derive(ctx, shared_key, &derived_keylen) <= 0)
            {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }

            return [NSData dataWithBytes:shared_key length:derived_keylen];
        } break;
    }
}


+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key {
    switch (key.signingSecretKey.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmEdDSA: {
            if (key.signingSecretKey.curveOID.curveKind != PGPCurveEd25519) {
                PGPLogWarning(@"Unsupported curve %@ kind for EdDSA algorithm", @(key.signingSecretKey.curveOID.curveKind));
                return @[];
            }

            let SEED = [[key.signingSecretKey secretMPI:PGPMPIdentifierD] bodyData]; //
            let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, SEED.bytes, SEED.length);
            if (!pkey) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return @[];
            }
            pgp_defer {
                EVP_PKEY_free(pkey);
            };

            let ctx = EVP_MD_CTX_new();
            pgp_defer {
                EVP_MD_CTX_free(ctx);
            };

            if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) <= 0) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return @[];
            }

            size_t siglen = 0;
            if (EVP_DigestSign(ctx, NULL, &siglen, toSign.bytes, toSign.length) <= 0) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return @[];
            }

            unsigned char *sigret = OPENSSL_malloc(siglen);
            pgp_defer {
                OPENSSL_clear_free(sigret, siglen);
            };
            if (EVP_DigestSign(ctx, sigret, &siglen, toSign.bytes, toSign.length) <= 0) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return @[];
            }
            let sigData = [NSData dataWithBytes:sigret length:siglen];
            // Is this even right?
            let RData = [sigData subdataWithRange:NSMakeRange(0, 32)];
            let SData = [sigData subdataWithRange:NSMakeRange(32, 32)];
            let rMPI = [[PGPMPI alloc] initWithData:RData identifier:PGPMPIdentifierR];
            let sMPI = [[PGPMPI alloc] initWithData:SData identifier:PGPMPIdentifierS];
            return @[rMPI, sMPI];
        } break;
        case PGPPublicKeyAlgorithmECDSA: {
            switch (key.signingSecretKey.curveOID.curveKind) {
                case PGPCurve25519:
                case PGPCurveEd25519:
                    // Not compatible with ECDSA
                    return @[];
                case PGPCurveP256:
                case PGPCurveP384:
                case PGPCurveP521:
                case PGPCurveBrainpoolP256r1:
                case PGPCurveBrainpoolP512r1:
                    // TODO: Implement ECDSA verification
                    break;
            }
        } break;
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmPrivate1:
        case PGPPublicKeyAlgorithmPrivate2:
        case PGPPublicKeyAlgorithmPrivate3:
        case PGPPublicKeyAlgorithmPrivate4:
        case PGPPublicKeyAlgorithmPrivate5:
        case PGPPublicKeyAlgorithmPrivate6:
        case PGPPublicKeyAlgorithmPrivate7:
        case PGPPublicKeyAlgorithmPrivate8:
        case PGPPublicKeyAlgorithmPrivate9:
        case PGPPublicKeyAlgorithmPrivate10:
        case PGPPublicKeyAlgorithmPrivate11:
            PGPLogDebug(@"EC Sign unsupported algorithm %@", @(key.signingSecretKey.publicKeyAlgorithm));
        break;
    }

    return @[];
}

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    switch (publicKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmEdDSA: {
            if (publicKeyPacket.curveOID.curveKind != PGPCurveEd25519) {
                PGPLogWarning(@"Unsupported curve %@ kind for EdDSA algorithm", @(publicKeyPacket.curveOID.curveKind));
                return NO;
            }

            let Q = [[publicKeyPacket publicMPI:PGPMPIdentifierQ] bodyData]; // public key
            let publicKey = [Q subdataWithRange:NSMakeRange(1, Q.length - 1)];
            let pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, publicKey.bytes, publicKey.length);
            if (!pkey) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return NO;
            }
            pgp_defer {
                EVP_PKEY_free(pkey);
            };

            let ctx = EVP_MD_CTX_new();
            pgp_defer {
                EVP_MD_CTX_free(ctx);
            };

            if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) <= 0) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return NO;
            }

            let r = [[signaturePacket signatureMPI:PGPMPIdentifierR] bodyData];
            let s = [[signaturePacket signatureMPI:PGPMPIdentifierS] bodyData];
            let signatureData = [NSMutableData data];
            [signatureData appendData:r];
            [signatureData appendData:s];

            let ret = EVP_DigestVerify(ctx, signatureData.bytes, signatureData.length, toVerify.bytes, toVerify.length);
            if (ret < 0) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return NO;
            }

            if (ret == 1) {
                return YES;
            }

        } break;
        case PGPPublicKeyAlgorithmECDSA:
            // TODO: Implement ECDSA verification
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        case PGPPublicKeyAlgorithmElgamal:
        case PGPPublicKeyAlgorithmDSA:
        case PGPPublicKeyAlgorithmECDH:
        case PGPPublicKeyAlgorithmElgamalEncryptorSign:
        case PGPPublicKeyAlgorithmDiffieHellman:
        case PGPPublicKeyAlgorithmPrivate1:
        case PGPPublicKeyAlgorithmPrivate2:
        case PGPPublicKeyAlgorithmPrivate3:
        case PGPPublicKeyAlgorithmPrivate4:
        case PGPPublicKeyAlgorithmPrivate5:
        case PGPPublicKeyAlgorithmPrivate6:
        case PGPPublicKeyAlgorithmPrivate7:
        case PGPPublicKeyAlgorithmPrivate8:
        case PGPPublicKeyAlgorithmPrivate9:
        case PGPPublicKeyAlgorithmPrivate10:
        case PGPPublicKeyAlgorithmPrivate11:
            PGPLogDebug(@"EC Verify unsupported algorithm %@", @(publicKeyPacket.publicKeyAlgorithm));
            return NO;
        break;
    }

    return NO;
}


@end

NS_ASSUME_NONNULL_END
