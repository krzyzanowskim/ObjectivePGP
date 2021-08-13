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
#import "PGPBigNum+Private.h"
#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

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
        case PGPCurveEd25519: {
            NSAssert(NO, @"Curve %@ is not handled.", @(curveKind));
            return nil;
        }
        case PGPCurve25519:
        {
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
            if (!ctx || EVP_PKEY_derive_init(ctx) <= 0
                || EVP_PKEY_derive_set_peer(ctx, pkey_public_key_V) <= 0
                || EVP_PKEY_derive(ctx, shared_key, &derived_keylen) <= 0)
            {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                OPENSSL_secure_free(shared_key);
                EVP_PKEY_CTX_free(ctx);
            };

            return [NSData dataWithBytes:shared_key length:derived_keylen];
        }
        break;
    }
}

@end

NS_ASSUME_NONNULL_END
