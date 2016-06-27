//
//  NSData+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+PGPUtils.h"
#import "PGPCryptoUtils.h"

#import <CommonCrypto/CommonCrypto.h>

#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>


@implementation NSData (PGPUtils)

/**
 *  Calculates a 16bit sum of a string by adding each character * codes modulus 65535
 *
 *  @return checksum
 */
- (UInt16) pgp_Checksum
{
    UInt32 s = 0;
    const UInt8 *bytes = self.bytes;
    for (NSUInteger i = 0; i < self.length; i++) {
        s = (s + (UInt8)bytes[i]);
    }
    s = s % 65536;
    return (UInt16)s;
}

#define CRC24_POLY 0x1864cfbL
#define CRC24_INIT 0xB704CEL

- (UInt32) pgp_CRC24
{
    UInt32 crc = CRC24_INIT;
    NSUInteger len = self.length;
    const UInt8 *octets = self.bytes;
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

- (NSData*) pgp_MD5
{
    if (!self)
        return self;

    CC_MD5_CTX *ctx = calloc(1, sizeof(CC_MD5_CTX));

    CC_MD5_Init(ctx);
    CC_MD5_Update(ctx, self.bytes, (CC_LONG)self.length);
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

- (NSData *) pgp_SHA1
{
    if (!self)
        return self;
    
//    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
//    CC_SHA1(self.bytes, self.length, digest);
//    NSData *outData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
    if (!ctx) {
        return nil;
    }

    UInt8 *outBuf = calloc(CC_SHA1_DIGEST_LENGTH, 1);
    if (!outBuf) {
        free(ctx);
        return nil;
    }
    CC_SHA1_Init(ctx);
    CC_SHA1_Update(ctx, self.bytes, (CC_LONG)self.length);
    CC_SHA1_Final(outBuf, ctx);

    NSData *outData = [NSData dataWithBytes:outBuf length:CC_SHA1_DIGEST_LENGTH];

    free(outBuf);
    free(ctx);
    return outData;
}

- (NSData*) pgp_SHA224
{
    if (!self)
        return self;

    CC_SHA256_CTX *ctx = calloc(1, sizeof(CC_SHA256_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA224_Init(ctx);
    CC_SHA224_Update(ctx, self.bytes, (CC_LONG)self.length);
    UInt8 *out = calloc(CC_SHA224_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        free(ctx);
        return nil;
    }
    CC_SHA224_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA224_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgp_SHA256
{
    if (!self)
        return self;

    CC_SHA256_CTX *ctx = calloc(1, sizeof(CC_SHA256_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA256_Init(ctx);
    CC_SHA256_Update(ctx, self.bytes, (CC_LONG)self.length);
    UInt8 *out = calloc(CC_SHA256_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        free(ctx);
        return nil;
    }
    CC_SHA256_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA256_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgp_SHA384
{
    if (!self)
        return self;

    CC_SHA512_CTX *ctx = calloc(1, sizeof(CC_SHA512_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA384_Init(ctx);
    CC_SHA384_Update(ctx, self.bytes, (CC_LONG)self.length);
    UInt8 *out = calloc(CC_SHA384_DIGEST_LENGTH, sizeof(UInt8));
    if (!out) {
        free(ctx);
        return nil;
    }
    CC_SHA384_Final(out, ctx);

    NSData *outData = [NSData dataWithBytes:out length:CC_SHA384_DIGEST_LENGTH];

    free(out);
    free(ctx);
    return outData;
}

- (NSData*) pgp_SHA512
{
    if (!self)
        return self;

    CC_SHA512_CTX *ctx = calloc(1, sizeof(CC_SHA512_CTX));
    if (!ctx) {
        return nil;
    }

    CC_SHA512_Init(ctx);
    CC_SHA512_Update(ctx, self.bytes, (CC_LONG)self.length);
    UInt8 *outBuf = calloc(CC_SHA512_DIGEST_LENGTH, sizeof(UInt8));
    if (!outBuf) {
        free(ctx);
        return nil;
    }
    CC_SHA512_Final(outBuf, ctx);

    NSData *outData = [NSData dataWithBytes:outBuf length:CC_SHA512_DIGEST_LENGTH];

    free(outBuf);
    free(ctx);
    return outData;
}

- (NSData*) pgp_RIPEMD160
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

- (NSData *) pgp_HashedWithAlgorithm:(PGPHashAlgorithm)hashAlgorithm
{
    NSData *hashData = nil;
    switch (hashAlgorithm) {
        case PGPHashMD5:
            hashData = [self pgp_MD5];
            break;
        case PGPHashSHA1:
            hashData = [self pgp_SHA1];
            break;
        case PGPHashSHA224:
            hashData = [self pgp_SHA224];
            break;
        case PGPHashSHA256:
            hashData = [self pgp_SHA256];
            break;
        case PGPHashSHA384:
            hashData = [self pgp_SHA384];
            break;
        case PGPHashSHA512:
            hashData = [self pgp_SHA512];
            break;
        case PGPHashRIPEMD160:
            hashData = [self pgp_RIPEMD160];
            break;

        default:
            NSAssert(false, @"hash algorithm not supported");
            break;
    }
    return hashData;
}

#pragma mark - Encryption

- (NSData *) pgp_encryptBlockWithSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    NSAssert(sessionKeyData,@"Missing key data");
    
    if (!sessionKeyData) {
        return nil;
    }
    
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:symmetricAlgorithm];

    NSData *ret = nil;
    
    switch (symmetricAlgorithm) {
        case PGPSymmetricCAST5:
        {
            CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(encrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
            UInt8 *outBuf = calloc(self.length, sizeof(UInt8));
            CAST_ecb_encrypt(self.bytes, outBuf, encrypt_key, CAST_ENCRYPT);
            ret = [NSData dataWithBytes:&outBuf length:self.length];

            free(outBuf);
            free(encrypt_key);
        }
            break;
        case PGPSymmetricAES256:
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        {
            AES_KEY *encrypt_key = calloc(1, sizeof(AES_KEY));
            AES_set_encrypt_key(sessionKeyData.bytes, keySize * 8.0, encrypt_key);

            UInt8 *outBuf = calloc(self.length, sizeof(UInt8));
            AES_encrypt(self.bytes, outBuf, encrypt_key);
            ret = [NSData dataWithBytes:&outBuf length:self.length];

            free(outBuf);
            free(encrypt_key);
        }
            break;
        case PGPSymmetricIDEA:
        {
            IDEA_KEY_SCHEDULE *encrypt_key = calloc(1, sizeof(IDEA_KEY_SCHEDULE));
            idea_set_encrypt_key(sessionKeyData.bytes, encrypt_key);

            UInt8 *outBuf = calloc(self.length, sizeof(UInt8));
            idea_ecb_encrypt(self.bytes, outBuf, encrypt_key);
            ret = [NSData dataWithBytes:&outBuf length:self.length];

            free(outBuf);
            free(encrypt_key);
        }
            break;
        case PGPSymmetricTripleDES:
        {
            // Very unsure if this is working, need some tests later
            const void *key = sessionKeyData.bytes;
            
            DES_key_schedule *keys3 = calloc(3, sizeof(DES_key_schedule));
            for (int n = 0; n < 3; ++n) {
                DES_set_key((DES_cblock *)(void *)(key + n * 8), &keys3[n]);
            }
            
            DES_cblock *outBuf = calloc(self.length, sizeof(DES_cblock));
            DES_ecb3_encrypt((void *)(unsigned long)(const void *)(self.bytes), outBuf, &keys3[0], &keys3[1], &keys3[2], DES_ENCRYPT);
            ret = [NSData dataWithBytes:&outBuf length:self.length];

            free(outBuf);
            free(keys3);
        }
            break;
        default:
            [NSException raise:@"PGPNotSupported" format:@"Encryption unsupported, cant encrypt data"];
            break;
    }
    return ret;
}


@end
