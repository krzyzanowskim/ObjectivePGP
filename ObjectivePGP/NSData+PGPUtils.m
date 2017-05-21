//
//  NSData+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+PGPUtils.h"
#import "PGPCryptoUtils.h"
#import "PGPCryptoHash.h"

#import <CommonCrypto/CommonCrypto.h>

#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>

NS_ASSUME_NONNULL_BEGIN

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

- (NSData*) pgp_MD5 {
    return PGPmd5(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *) pgp_SHA1 {
    return PGPsha1(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData*) pgp_SHA224 {
    return PGPsha224(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData*) pgp_SHA256 {
    return PGPsha256(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData*) pgp_SHA384 {
    return PGPsha384(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData*) pgp_SHA512 {
    return PGPsha512(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData*) pgp_RIPEMD160 {
    return PGPripemd160(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *) pgp_HashedWithAlgorithm:(PGPHashAlgorithm)hashAlgorithm
{
    return PGPCalculateHash(hashAlgorithm, ^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
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
            AES_set_encrypt_key(sessionKeyData.bytes, (int)(keySize * 8), encrypt_key);

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

NS_ASSUME_NONNULL_END

