//
//  PGPCryptoHash.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 22/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCryptoHash.h"
#import <openssl/ripemd.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NSData * _Nullable PGPCalculateHash(PGPHashAlgorithm algorithm, NOESCAPE PGPUpdateBlock update) {
    switch (algorithm) {
        case PGPHashMD5:
            return PGPmd5(update);
        case PGPHashSHA1:
            return PGPsha1(update);
        case PGPHashSHA224:
            return PGPsha224(update);
        case PGPHashSHA256:
            return PGPsha256(update);
        case PGPHashSHA384:
            return PGPsha384(update);
        case PGPHashSHA512:
            return PGPsha512(update);
        case PGPHashRIPEMD160:
            return PGPripemd160(update);
        default:
            assert(@"hash algorithm not supported");
    }
    return nil;
}

#define commonHashImpl(name,INITfn,UPDATEfn,FINALfn,CTX,DIGEST_LENGTH) \
NSData * _Nullable PGP##name(NOESCAPE PGPUpdateBlock update) \
{ \
    let ctx = calloc(1, sizeof(CTX)); \
    if (!ctx) { \
        return nil; \
    } \
\
    INITfn(ctx); \
\
    if (update) { \
        update(^(const void *data, int lenght) { \
            UPDATEfn(ctx, data, (CC_LONG)lenght); \
        }); \
    } \
\
    UInt8 *outbuf = calloc(DIGEST_LENGTH, sizeof(UInt8)); \
    if (!outbuf) { \
        free(ctx); \
        return nil; \
    } \
    FINALfn(outbuf, ctx); \
\
    let outData = [NSData dataWithBytes:outbuf length:DIGEST_LENGTH]; \
\
    free(outbuf); \
    free(ctx); \
\
    return outData; \
}

commonHashImpl(md5,CC_MD5_Init,CC_MD5_Update,CC_MD5_Final,CC_MD5_CTX,CC_MD5_DIGEST_LENGTH)
commonHashImpl(sha1,CC_SHA1_Init,CC_SHA1_Update,CC_SHA1_Final,CC_SHA1_CTX,CC_SHA1_DIGEST_LENGTH)
commonHashImpl(sha224,CC_SHA224_Init,CC_SHA224_Update,CC_SHA224_Final,CC_SHA256_CTX,CC_SHA224_DIGEST_LENGTH)
commonHashImpl(sha256,CC_SHA256_Init,CC_SHA256_Update,CC_SHA256_Final,CC_SHA256_CTX,CC_SHA256_DIGEST_LENGTH)
commonHashImpl(sha384,CC_SHA384_Init,CC_SHA384_Update,CC_SHA384_Final,CC_SHA512_CTX,CC_SHA384_DIGEST_LENGTH)
commonHashImpl(sha512,CC_SHA512_Init,CC_SHA512_Update,CC_SHA512_Final,CC_SHA512_CTX,CC_SHA512_DIGEST_LENGTH)
commonHashImpl(ripemd160,RIPEMD160_Init,RIPEMD160_Update,RIPEMD160_Final,RIPEMD160_CTX,RIPEMD160_DIGEST_LENGTH)

NS_ASSUME_NONNULL_END
