//
//  PGPCryptoCFB.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCryptoCFB.h"
#import "PGPTypes.h"
#import "PGPS2K.h"
#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>

@implementation PGPCryptoCFB

+ (NSData *) decryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData
{
    return [[self class] manipulateData:encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData decrypt:YES];
}

+ (NSData *) encryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData
{
    return [[self class] manipulateData:encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData decrypt:NO];
}

#pragma mark - Private

// key binary string representation of key to be used to decrypt the ciphertext.
+ (NSData *) manipulateData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData
                 decrypt:(BOOL)decrypt
{
    NSAssert(ivData.length > 0, @"Missing IV");
    
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:symmetricAlgorithm];
    NSAssert(keySize <= 32, @"invalid keySize");
    
    const void *encryptedBytes = encryptedData.bytes;
    NSUInteger outButterLength = encryptedData.length;
    UInt8 *outBuffer = calloc(outButterLength, sizeof(UInt8));
    
    NSData *decryptedData = nil;
    
    // decrypt with CFB
    switch (symmetricAlgorithm) {
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        case PGPSymmetricAES256:
        {
            AES_KEY *encrypt_key = calloc(1, sizeof(AES_KEY));
            AES_set_encrypt_key(sessionKeyData.bytes, (unsigned int)keySize * 8, encrypt_key);
            
            AES_KEY *decrypt_key = calloc(1, sizeof(AES_KEY));
            AES_set_decrypt_key(sessionKeyData.bytes, (unsigned int)keySize * 8, decrypt_key);
            
            int num = 0;
            AES_cfb128_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)ivData.bytes, &num, decrypt ? AES_DECRYPT : AES_ENCRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
            
            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;
        case PGPSymmetricIDEA:
        {
            IDEA_KEY_SCHEDULE *encrypt_key = calloc(1, sizeof(IDEA_KEY_SCHEDULE));
            idea_set_encrypt_key(sessionKeyData.bytes, encrypt_key);
            
            IDEA_KEY_SCHEDULE *decrypt_key = calloc(1, sizeof(IDEA_KEY_SCHEDULE));
            idea_set_decrypt_key(encrypt_key, decrypt_key);
            
            int num = 0;
            idea_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)ivData.bytes, &num, decrypt ? CAST_DECRYPT : CAST_ENCRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
            
            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;
        case PGPSymmetricTripleDES:
        {
            DES_key_schedule *keys = calloc(3, sizeof(DES_key_schedule));
            
            for (NSUInteger n = 0; n < 3; ++n) {
                DES_set_key((DES_cblock *)(void *)(ivData.bytes + n * 8),&keys[n]);
            }
            
            int num = 0;
            DES_ede3_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, &keys[0], &keys[1], &keys[2], (DES_cblock *)(void *)ivData.bytes, &num, decrypt ? DES_DECRYPT : DES_ENCRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
            
            if (keys) free(keys);
        }
            break;
        case PGPSymmetricCAST5:
        {
            // initialize
            CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(encrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
            
            CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(decrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
            
            // see __ops_decrypt_init block_encrypt siv,civ,iv comments. siv is needed for weird v3 resync,
            // wtf civ ???
            // CAST_ecb_encrypt(in, out, encrypt_key, CAST_ENCRYPT);
            
            int num = 0; //	how much of the 64bit block we have used
            CAST_cfb64_encrypt(encryptedBytes, outBuffer, outButterLength, decrypt_key, (UInt8 *)ivData.bytes, &num, decrypt ? CAST_DECRYPT : CAST_ENCRYPT);
            decryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
            
            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
        }
            break;
        case PGPSymmetricBlowfish:
        case PGPSymmetricTwofish256:
            //TODO: implement blowfish and twofish
            [NSException raise:@"PGPNotSupported" format:@"Twofish not supported"];
            break;
        case PGPSymmetricPlaintext:
            [NSException raise:@"PGPInconsistency" format:@"Can't decrypt plaintext"];
            break;
        default:
            break;
    }
    
    if (outBuffer) {
        memset(outBuffer, 0, sizeof(UInt8));
        free(outBuffer);
    }
    
    return [decryptedData copy];
}

@end
