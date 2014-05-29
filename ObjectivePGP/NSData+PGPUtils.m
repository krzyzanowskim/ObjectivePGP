//
//  NSData+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+PGPUtils.h"
#import <CommonCrypto/CommonDigest.h>
#include <openssl/ripemd.h>

@implementation NSData (PGPUtils)

/**
 *  Calculates a 16bit sum of a string by adding each character * codes modulus 65535
 *
 *  @return checksum
 */
- (UInt16) pgpChecksum
{
    UInt16 s = 0;
    UInt8 *bytes = (UInt8 *)self.bytes;
    for (NSUInteger i = 0; i < self.length; i++) {
        s = (s + (UInt8)bytes[i]);
    }
    s = s % 65536;
    return s;
}

#define CRC24_POLY 0x1864cfbL
#define CRC24_INIT 0xB704CEL

- (UInt32) pgpCRC24
{
    UInt32 crc = CRC24_INIT;
    NSUInteger len = self.length;
    UInt8 *octets = (UInt8 *)self.bytes;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}

- (NSData*) pgpMD5
{
    if (!self)
        return self;

    CC_MD5_CTX *ctx = calloc(1, sizeof(CC_MD5_CTX));

    CC_MD5_Init(ctx);
    CC_MD5_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_MD5_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        free(ctx);
        return nil;
    }
    CC_MD5_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_MD5_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData *) pgpSHA1
{
    if (!self)
        return self;
    
    CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA1_Init(ctx);
    CC_SHA1_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA1_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA1_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA1_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgpSHA224
{
    if (!self)
        return self;

    CC_SHA256_CTX *ctx = calloc(1, sizeof(CC_SHA256_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA224_Init(ctx);
    CC_SHA224_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA224_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA224_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA224_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgpSHA256
{
    if (!self)
        return self;

    CC_SHA256_CTX *ctx = calloc(1, sizeof(CC_SHA256_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA256_Init(ctx);
    CC_SHA256_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA256_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA256_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA256_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgpSHA384
{
    if (!self)
        return self;

    CC_SHA512_CTX *ctx = calloc(1, sizeof(CC_SHA512_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA384_Init(ctx);
    CC_SHA384_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA512_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA384_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA384_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgpSHA512
{
    if (!self)
        return self;

    CC_SHA512_CTX *ctx = calloc(1, sizeof(CC_SHA512_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA512_Init(ctx);
    CC_SHA512_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(CC_SHA512_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    CC_SHA512_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA512_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgpRIPEMD160
{
    if (!self)
        return self;

    RIPEMD160_CTX *ctx = calloc(1, sizeof(RIPEMD160_CTX));
    if (!ctx) {
        return nil;
    }

    RIPEMD160_Init(ctx);
    RIPEMD160_Update(ctx, self.bytes, self.length);
    UInt8 *out = calloc(RIPEMD160_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        return nil;
    }
    RIPEMD160_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:RIPEMD160_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData *) pgpHashedWithAlgorithm:(PGPHashAlgorithm)hashAlgorithm
{
    NSData *hashData = nil;
    switch (hashAlgorithm) {
        case PGPHashMD5:
            hashData = [self pgpMD5];
            break;
        case PGPHashSHA1:
            hashData = [self pgpSHA1];
            break;
        case PGPHashSHA224:
            hashData = [self pgpSHA224];
            break;
        case PGPHashSHA256:
            hashData = [self pgpSHA256];
            break;
        case PGPHashSHA384:
            hashData = [self pgpSHA384];
            break;
        case PGPHashSHA512:
            hashData = [self pgpSHA512];
            break;
        case PGPHashRIPEMD160:
            hashData = [self pgpRIPEMD160];
            break;

        default:
            NSAssert(false, @"hash algorithm not supported");
            break;
    }
    return hashData;
}


@end
