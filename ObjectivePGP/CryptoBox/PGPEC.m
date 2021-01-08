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
#import "PGPBigNum+Private.h"

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
+ (nullable NSData *)generatePrivateEphemeralKeyWith:(NSData *)publicKeyEphemeralPart andSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket {
    switch (secretKeyPacket.curveOID.curveKind) {
        case PGPCurveP256:
        case PGPCurveP384:
        case PGPCurveP521:
        case PGPCurveBrainpoolP256r1:
        case PGPCurveBrainpoolP512r1:
        case PGPCurveEd25519: {
            NSAssert(NO, @"Curve %@ is not handled.", @(secretKeyPacket.curveOID.curveKind));
            return nil;
        }
        case PGPCurve25519:
        {
            let D = [[secretKeyPacket secretMPI:PGPMPIdentifierD] bodyData]; // private key

            // reverse bytes
            let reversedD = [[NSMutableData alloc] initWithCapacity:D.length];
            for (int i = (int)D.length - 1; i >= 0; i--) {
                [reversedD appendBytes:&D.bytes[i] length:1];
            }

            let privateKeyD = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, reversedD.bytes, reversedD.length);
            if (!privateKeyD) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                EVP_PKEY_free(privateKeyD);
            };

            let V = [publicKeyEphemeralPart subdataWithRange:NSMakeRange(1, publicKeyEphemeralPart.length - 1)]; // public key
            let publicKeyV = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, V.bytes , V.length);
            if (!publicKeyV) {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                EVP_PKEY_free(publicKeyV);
            };

            size_t derived_keylen = 32;
            let skey = OPENSSL_secure_malloc(derived_keylen);
            let ctx = EVP_PKEY_CTX_new(privateKeyD, NULL);
            if (!ctx || EVP_PKEY_derive_init(ctx) <= 0
                || EVP_PKEY_derive_set_peer(ctx, publicKeyV) <= 0
                || EVP_PKEY_derive(ctx, skey, &derived_keylen) <= 0)
            {
                char *err_str = ERR_error_string(ERR_get_error(), NULL);
                PGPLogDebug(@"%@", [NSString stringWithCString:err_str encoding:NSASCIIStringEncoding]);
                return nil;
            }
            pgp_defer {
                OPENSSL_secure_free(skey);
                EVP_PKEY_CTX_free(ctx);
            };

            return [NSData dataWithBytes:skey length:derived_keylen];
        }
        break;
    }
}

@end

NS_ASSUME_NONNULL_END
