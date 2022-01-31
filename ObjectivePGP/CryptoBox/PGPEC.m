//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPEC.h"
#import "PGPMPI.h"
#import "PGPKeyMaterial.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPPublicKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPKey.h"
#import "PGPBigNum+Private.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPCryptoUtils.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

#import <openssl/err.h>
#import <openssl/ssl.h>
#import <openssl/evp.h>
#import <openssl/aes.h>

#import <openssl/ec.h>
#import <openssl/ecdh.h>
#import <openssl/ecdsa.h>
#import <openssl/ecerr.h>

#import <openssl/bn.h>
#import <openssl/rsa.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPEC

/// Generate ECDHE secret from private key and public part of ephemeral key
+ (nullable NSData *)generate25519PrivateEphemeralKeyWith:(NSData *)publicPartEphemeralKey curveKind:(PGPCurve)curveKind privateKey:(NSData *)privateKeyData {
    // secret_key = reverse D bytes
    let secret_key = [privateKeyData pgp_reversed];
    let pkey_private_key_D = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key.bytes, secret_key.length);
    if (!pkey_private_key_D) {
        #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
        #endif
        return nil;
    }
    pgp_defer {
        EVP_PKEY_free(pkey_private_key_D);
    };

    let V = [publicPartEphemeralKey subdataWithRange:NSMakeRange(1, publicPartEphemeralKey.length - 1)]; // public key
    let pkey_public_key_V = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, V.bytes , V.length);
    if (!pkey_public_key_V) {
        #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
        #endif
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
        #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
        char *err_str = ERR_error_string(ERR_get_error(), NULL);
        PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
        #endif
        return nil;
    }

    return [NSData dataWithBytes:shared_key length:derived_keylen];
}

+ (nullable NSData *)generate25519PublicEphemeralKeyWith:(PGPPublicKeyPacket *)publicKeyPacket sharedKey:(NSData * __autoreleasing _Nullable *)shared  {
    let curveKind = publicKeyPacket.curveOID.curveKind;

    let private_key_d = [PGPCryptoUtils randomData:32];
    let secret_key = [private_key_d pgp_reversed];
    let pkey_private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key.bytes , secret_key.length);
    if (!pkey_private_key) {
        // TODO: set error
        return nil;
    }
    pgp_defer {
        EVP_PKEY_free(pkey_private_key);
    };

    // get public key from private key
    size_t public_key_buf_length = 0;
    if (EVP_PKEY_get_raw_public_key(pkey_private_key, NULL, &public_key_buf_length) == 0) {
        return nil;
    }

    unsigned char *public_key_buffer = OPENSSL_secure_malloc(public_key_buf_length);
    pgp_defer {
        OPENSSL_secure_clear_free(public_key_buffer, public_key_buf_length);
    };

    if (EVP_PKEY_get_raw_public_key(pkey_private_key, public_key_buffer, &public_key_buf_length) == 0) {
        return nil;
    }

    // 0x40 | public_key
    let public_key = [NSMutableData data];
    [public_key pgp_appendByte:0x40];
    [public_key appendBytes:public_key_buffer length:public_key_buf_length];

    // shared key
    let Q = [[publicKeyPacket publicMPI:PGPMPIdentifierQ] bodyData]; // publicKey
    let sharedKey = [PGPEC generate25519PrivateEphemeralKeyWith:Q curveKind:curveKind privateKey:private_key_d];

    if (shared) {
        *shared = sharedKey;
    }
    return public_key;
}

+ (BOOL)publicEncrypt:(nonnull NSData *)data withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket publicKey:(NSData * __autoreleasing _Nullable *)publicKey encodedSymmetricKey:(NSData * __autoreleasing _Nullable *)encodedSymmetricKey {
    switch (publicKeyPacket.curveOID.curveKind) {
        case PGPCurve25519: {
            NSData *sharedKey = nil;

            if (publicKey) {
                *publicKey = [self generate25519PublicEphemeralKeyWith:publicKeyPacket sharedKey:&sharedKey]; // X25519
            }

            // Build symmetric key wrapped and encoded using sharedKey

            // kdf param
            // - The KDF parameters https://datatracker.ietf.org/doc/html/rfc6637#section-8
            let kdfParam = [NSMutableData data];
            // one-octet size of the following field. the octets representing a curve OID
            [kdfParam pgp_appendData:[publicKeyPacket.curveOID export:nil]];
            // one-octet public key algorithm ID
            //[kdfParam appendBytes:&keyAlgorithm length:1];
            [kdfParam pgp_appendByte:publicKeyPacket.publicKeyAlgorithm];
            // KDF params
            [kdfParam pgp_appendData:[publicKeyPacket.curveKDFParameters export:nil]];
            // 20 octets representing the UTF-8 encoding of the string "Anonymous Sender    "
            const unsigned char anonymous_sender[] = {0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20};
            [kdfParam appendBytes:anonymous_sender length:20];
            // 20 octets representing a recipient encryption subkey or a master key fingerprint
            [kdfParam pgp_appendData:publicKeyPacket.fingerprint.hashedData];
            // KDF produces a symmetric key that is used as a key-encryption key (KEK)
            // https://datatracker.ietf.org/doc/html/rfc6637#section-7
            const unsigned char prefix_bytes[] = {0x00, 0x00, 0x00, 0x01};
            let kdfInput =  [NSMutableData dataWithBytes:prefix_bytes length:4];
            [kdfInput pgp_appendData:sharedKey];
            [kdfInput pgp_appendData:kdfParam];

            // truncated KEK
            let KEK = [[kdfInput pgp_HashedWithAlgorithm:publicKeyPacket.curveKDFParameters.hashAlgorithm] subdataWithRange:NSMakeRange(0, [PGPCryptoUtils keySizeOfSymmetricAlgorithm:publicKeyPacket.curveKDFParameters.symmetricAlgorithm])];

            // Add PKCS5 padding
            let paddedData = [data pgp_PKCS5Padded];

            // Key wrap
            AES_KEY *aes_key = OPENSSL_secure_malloc(sizeof(AES_KEY));
            pgp_defer {
                OPENSSL_secure_clear_free(aes_key, sizeof(AES_KEY));
            };

            if (AES_set_encrypt_key(KEK.bytes, (int)KEK.length * sizeof(UInt64), aes_key) < 0) {
                return NO;
            }

            if (AES_set_encrypt_key(KEK.bytes, (int)KEK.length * sizeof(UInt64), aes_key) < 0) {
                return NO;
            }

            unsigned long wrapped_buf_length = paddedData.length + sizeof(UInt64);
            unsigned char *wrapped_buf = OPENSSL_secure_malloc(wrapped_buf_length);
            pgp_defer {
                OPENSSL_secure_clear_free(wrapped_buf, wrapped_buf_length);
            };

            if (AES_wrap_key(aes_key, NULL, wrapped_buf, paddedData.bytes, (int)paddedData.length) <= 0) {
                return NO;
            }

            if (encodedSymmetricKey) {
                *encodedSymmetricKey = [NSData dataWithBytes:wrapped_buf length:wrapped_buf_length];
            }

            return YES;
        } break;
        case PGPCurveEd25519: {
            NSAssert(NO,@"ED25519 is not used for encryption");
            return NO;
        } break;
        case PGPCurveP256:
        case PGPCurveP384:
        case PGPCurveP521:
            // ellipticPrivateEphemeralKey
        case PGPCurveBrainpoolP256r1:
        case PGPCurveBrainpoolP512r1:
            // TODO: Implement!
            break;
    }

    return NO;
}

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key withHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm {
    switch (key.signingSecretKey.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmEdDSA: {
            if (key.signingSecretKey.curveOID.curveKind != PGPCurveEd25519) {
                PGPLogWarning(@"Unsupported curve %@ kind for EdDSA algorithm", @(key.signingSecretKey.curveOID.curveKind));
                return @[];
            }
        
            let SEED = [[key.signingSecretKey secretMPI:PGPMPIdentifierD] bodyData]; //
            let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, SEED.bytes, SEED.length);
            if (!pkey) {
                #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                #endif
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
                #if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                #endif
                return @[];
            }
            
            NSData* hash = [toSign pgp_HashedWithAlgorithm:hashAlgorithm];
            size_t siglen = 0;
            
            if (EVP_DigestSign(ctx, NULL, &siglen, hash.bytes, hash.length) <= 0) {
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
                return @[];
            }

            unsigned char *sigret = OPENSSL_malloc(siglen);
            pgp_defer {
                OPENSSL_clear_free(sigret, siglen);
            };
            if (EVP_DigestSign(ctx, sigret, &siglen, hash.bytes, hash.length) <= 0) {
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
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

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket withHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm {
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
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
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
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
                return NO;
            }

            let r = [[signaturePacket signatureMPI:PGPMPIdentifierR] bodyData];
            let s = [[signaturePacket signatureMPI:PGPMPIdentifierS] bodyData];
            let signatureData = [NSMutableData data];
            [signatureData appendData:r];
            [signatureData appendData:s];
            
            NSData* hash = [toVerify pgp_HashedWithAlgorithm:hashAlgorithm];
            
            //let ret = EVP_DigestVerify(ctx, signatureData.bytes, signatureData.length, toVerify.bytes, toVerify.length);
            let ret = EVP_DigestVerify(ctx, signatureData.bytes, signatureData.length, hash.bytes, hash.length);
            if (ret < 0) {
#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
#endif
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

+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(PGPCurve)curve {
    
    let keyMaterial = [[PGPKeyMaterial alloc] init];
    int curveID = - 1;
    
    switch(curve) {
        case PGPCurve25519:
            curveID = EVP_PKEY_X25519;
            break;
        case PGPCurveEd25519:
            curveID = EVP_PKEY_ED25519;
            break;
        case PGPCurveP256:
        case PGPCurveP384:
        case PGPCurveP521:
        case PGPCurveBrainpoolP256r1:
        case PGPCurveBrainpoolP512r1:
            // TODO: implement NIST curves
            curveID = -1;
            break;
    }

    if (curveID == -1) {
        return nil;
    }
    
    NSData* private_key_d = [[PGPCryptoUtils randomData:32] mutableCopy];
    let secret_key = [private_key_d pgp_reversed];
    let pkey_private_key = EVP_PKEY_new_raw_private_key(curveID, NULL, secret_key.bytes , secret_key.length);
    if (!pkey_private_key) {
        // TODO: set error
        return nil;
    }
    pgp_defer {
        EVP_PKEY_free(pkey_private_key);
    };

    // get public key from private key
    size_t public_key_buf_length = 0;
    if (EVP_PKEY_get_raw_public_key(pkey_private_key, NULL, &public_key_buf_length) == 0) {
        return nil;
    }

    unsigned char *public_key_buffer = OPENSSL_secure_malloc(public_key_buf_length);
    pgp_defer {
        OPENSSL_secure_clear_free(public_key_buffer, public_key_buf_length);
    };

    if (EVP_PKEY_get_raw_public_key(pkey_private_key, public_key_buffer, &public_key_buf_length) == 0) {
        return nil;
    }

    // 0x40 | public_key
    let public_key = [NSMutableData data];
    [public_key pgp_appendByte:0x40];
    [public_key appendBytes:public_key_buffer length:public_key_buf_length];
    
    // Ed25519 private key MPI should be in little-endian order
    // https://www.gniibe.org/log/bugreport/openpgp/ecc-in-openpgp.html
    let private_key = [NSMutableData data];
    [private_key appendBytes:(curve == PGPCurveEd25519 ? secret_key.bytes : private_key_d.bytes) length:(curve == PGPCurveEd25519 ? secret_key.length : private_key_d.length)];
    
    let mpiQ = [[PGPMPI alloc] initWithData:public_key identifier:PGPMPIdentifierQ];
    var mpiD = [[PGPMPI alloc] initWithData:private_key identifier:PGPMPIdentifierD];
    
    keyMaterial.q = mpiQ;
    keyMaterial.d = mpiD;
    
    return keyMaterial;
}

@end

NS_ASSUME_NONNULL_END
