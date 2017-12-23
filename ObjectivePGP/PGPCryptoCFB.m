//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPCryptoCFB.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPCryptoUtils.h"
#import "PGPS2K.h"
#import "PGPTypes.h"
#import "PGPMacros+Private.h"
#import "PGPLogging.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <openssl/aes.h>
#import <openssl/blowfish.h>
#import <openssl/camellia.h>
#import <openssl/cast.h>
#import <openssl/des.h>
#import <openssl/idea.h>
#import <openssl/sha.h>

#import "twofish.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPCryptoCFB

+ (nullable NSData *)decryptData:(NSData *)encryptedData
                  sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
              symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                              iv:(NSData *)ivData
                         syncCFB:(BOOL)syncCFB
{
    return [self manipulateData:encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData syncCFB:syncCFB decrypt:YES];
}

+ (nullable NSData *)encryptData:(NSData *)encryptedData
                  sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
              symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                              iv:(NSData *)ivData
                         syncCFB:(BOOL)syncCFB
{
    return [self manipulateData:encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData syncCFB:syncCFB decrypt:NO];
}

#pragma mark - Private

// key binary string representation of key to be used to decrypt the ciphertext.
+ (nullable NSData *)manipulateData:(NSData *)encryptedData
                     sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
                 symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                                 iv:(NSData *)ivData
                           syncCFB:(BOOL)syncCFB // weird OpenPGP CFB
                            decrypt:(BOOL)decrypt
{
    NSAssert(sessionKeyData.length > 0, @"Missing session key");
    NSAssert(encryptedData.length > 0, @"Missing data");
    NSAssert(ivData.length > 0, @"Missing IV");

    if (ivData.length == 0 || sessionKeyData.length == 0 || encryptedData.length == 0) {
        return nil;
    }

    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:symmetricAlgorithm];
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];
    NSAssert(keySize <= 32, @"Invalid key size");
    NSAssert(sessionKeyData.length >= keySize, @"Invalid session key.");

    let ivDataBytes = (uint8_t *)[NSMutableData dataWithData:ivData].mutableBytes;
    let encryptedBytes = (const uint8_t *)encryptedData.bytes;
    var decryptedData = [NSMutableData dataWithLength:encryptedData.length];
    let outBuffer = (uint8_t *)decryptedData.mutableBytes;
    let outBufferLength = decryptedData.length;

    // decrypt with CFB
    switch (symmetricAlgorithm) {
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        case PGPSymmetricAES256: {
            AES_KEY aes_key;
            AES_set_encrypt_key(sessionKeyData.bytes, MIN((int)keySize * 8, (int)sessionKeyData.length * 8), &aes_key);

            int blocksNum = 0;
            AES_cfb128_encrypt(encryptedBytes, outBuffer, outBufferLength, &aes_key, ivDataBytes, &blocksNum, decrypt ? AES_DECRYPT : AES_ENCRYPT);

            memset(&aes_key, 0, sizeof(AES_KEY));
        } break;
        case PGPSymmetricIDEA: {
            IDEA_KEY_SCHEDULE encrypt_key;
            idea_set_encrypt_key(sessionKeyData.bytes, &encrypt_key);

            IDEA_KEY_SCHEDULE decrypt_key;
            idea_set_decrypt_key(&encrypt_key, &decrypt_key);

            int num = 0;
            idea_cfb64_encrypt(encryptedBytes, outBuffer, outBufferLength, decrypt ? &decrypt_key : &encrypt_key, ivDataBytes, &num, decrypt ? CAST_DECRYPT : CAST_ENCRYPT);

            memset(&encrypt_key, 0, sizeof(IDEA_KEY_SCHEDULE));
            memset(&decrypt_key, 0, sizeof(IDEA_KEY_SCHEDULE));
        } break;
        case PGPSymmetricTripleDES: {
            DES_key_schedule *keys = calloc(3, sizeof(DES_key_schedule));
            pgp_defer {
                if (keys) {
                    memset(keys, 0, 3 * sizeof(DES_key_schedule));
                    free(keys);
                }
            };

            for (NSUInteger n = 0; n < 3; ++n) {
                DES_set_key((DES_cblock *)(void *)(sessionKeyData.bytes + n * 8), &keys[n]);
            }

            int blocksNum = 0;
            DES_ede3_cfb64_encrypt(encryptedBytes, outBuffer, outBufferLength, &keys[0], &keys[1], &keys[2], (DES_cblock *)(void *)ivDataBytes, &blocksNum, decrypt ? DES_DECRYPT : DES_ENCRYPT);
        } break;
        case PGPSymmetricCAST5: {
            // initialize
            CAST_KEY encrypt_key;
            CAST_set_key(&encrypt_key, MIN((int)keySize, (int)sessionKeyData.length), sessionKeyData.bytes);

            // CAST_ecb_encrypt(in, out, encrypt_key, CAST_ENCRYPT);
            int num = 0; //	how much of the 64bit block we have used
            CAST_cfb64_encrypt(encryptedBytes, outBuffer, outBufferLength, &encrypt_key, ivDataBytes, &num, decrypt ? CAST_DECRYPT : CAST_ENCRYPT);

            memset(&encrypt_key, 0, sizeof(CAST_KEY));
        } break;
        case PGPSymmetricBlowfish: {
            BF_KEY encrypt_key;
            BF_set_key(&encrypt_key, MIN((int)keySize, (int)sessionKeyData.length), sessionKeyData.bytes);

            int num = 0; //    how much of the 64bit block we have used
            BF_cfb64_encrypt(encryptedBytes, outBuffer, outBufferLength, &encrypt_key, ivDataBytes, &num, decrypt ? BF_DECRYPT : BF_ENCRYPT);

            memset(&encrypt_key, 0, sizeof(BF_KEY));
        } break;
        /*
        case PGPSymmetricTwofish256: {
            static dispatch_once_t twoFishInit;
            dispatch_once(&twoFishInit, ^{ Twofish_initialise(); });

            Twofish_key xkey;
            Twofish_prepare_key((uint8_t *)sessionKeyData.bytes, (int)sessionKeyData.length, &xkey);

            // FIXME: OpenPGP CFB Mode is different here
            // CFB
            NSUInteger blockLength = ivData.length;
            if (!decrypt) {
                // encrypt
                NSMutableData *encryptedOutMutableData = encryptedData.mutableCopy;
                NSData *plaintext = ivData.copy;
                for (NSUInteger index = 0; index < encryptedData.length; index += blockLength) {
                    let ciphertext = [NSMutableData dataWithLength:blockLength];
                    Twofish_encrypt(&xkey, (uint8_t *)plaintext.bytes, ciphertext.mutableBytes);
                    [encryptedOutMutableData XORWithData:ciphertext index:index];
                    plaintext = [encryptedOutMutableData subdataWithRange:(NSRange){index ,blockLength}]; // ciphertext.copy;
                }
                decryptedData = encryptedOutMutableData.copy;
            } else {
                // decrypt
                NSMutableData *decryptedOutMutableData = encryptedData.mutableCopy;
                NSData *ciphertext = ivData.copy;
                for (NSUInteger index = 0; index < encryptedData.length; index += blockLength) {
                    NSMutableData *plaintext = [NSMutableData dataWithLength:blockLength];
                    Twofish_encrypt(&xkey, (uint8_t *)ciphertext.bytes, plaintext.mutableBytes);
                    [decryptedOutMutableData XORWithData:plaintext index:index];
                    ciphertext = [decryptedOutMutableData subdataWithRange:(NSRange){index ,blockLength}];
                }
                decryptedData = decryptedOutMutableData.copy;
            }

            memset(&xkey, 0, sizeof(Twofish_key));
        } break;
        */
        case PGPSymmetricPlaintext:
            PGPLogWarning(@"Can't decrypt plaintext");
            decryptedData = [NSMutableData dataWithData:encryptedData];
            break;
        default:
            PGPLogWarning(@"Unsupported cipher.");
            return nil;
    }

    return decryptedData;
}

@end

NS_ASSUME_NONNULL_END
