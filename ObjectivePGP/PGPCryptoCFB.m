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
        PGPLogDebug(@"Invalid input to encrypt/decrypt.");
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
            if (syncCFB) {
                /*
                 * https://tools.ietf.org/html/rfc4880#section-13.9
                 * In order to support weird resyncing we have to implement CFB mode ourselves
                 */

                //TODO: refactor it out and reuse for all ciphers
                AES_KEY aes_key;
                AES_set_encrypt_key(sessionKeyData.bytes, (int)keySize * 8, &aes_key);

                let BS = blockSize;
                // 1. The feedback register (FR) is set to the IV, which is all zeros.
                var FR = [NSData dataWithData:ivData];
                // 2.  FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
                var FRE = [NSMutableData dataWithLength:FR.length];
                AES_encrypt(FR.bytes, FRE.mutableBytes, &aes_key);
                // 4. FR is loaded with C[1] through C[BS].
                FR = [encryptedData subdataWithRange:(NSRange){0,BS}];
                // 3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
                let prefix = [NSData xor:FRE d2:FR];
                // 5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
                AES_encrypt(FR.bytes, FRE.mutableBytes, &aes_key);
                // 6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
                if (![[prefix subdataWithRange:(NSRange){BS - 2, 2}] isEqual:[NSData xor:[FRE subdataWithRange:(NSRange){0, 2}] d2:[encryptedData subdataWithRange:(NSRange){BS, 2}]]]) {
                    PGPLogDebug(@"Bad OpenPGP CFB check value");
                    return nil;
                }

                NSMutableData *plaintext = [NSMutableData dataWithCapacity:encryptedData.length];
                var x = 2;
                while ((BS + x) < encryptedData.length) {
                    let chunk = [encryptedData subdataWithRange:(NSRange){x, BS}];
                    [plaintext appendData:[NSData xor:FRE d2:chunk]];
                    AES_encrypt(chunk.bytes, FRE.mutableBytes, &aes_key);
                    x += BS;
                }
                [plaintext appendData:[NSData xor:FRE d2:[encryptedData subdataWithRange:(NSRange){x, MIN(BS,encryptedData.length - x)}]]];
                plaintext = [NSMutableData dataWithData:[plaintext subdataWithRange:(NSRange){BS, plaintext.length - BS}]];

                let result = [NSMutableData data];
                [result appendData:prefix];
                [result appendData:[prefix subdataWithRange:(NSRange){BS - 2, 2}]];
                [result appendData:plaintext];

                decryptedData = result;
                memset(&aes_key, 0, sizeof(AES_KEY));
            } else {
                AES_KEY aes_key;
                AES_set_encrypt_key(sessionKeyData.bytes, MIN((int)keySize * 8, (int)sessionKeyData.length * 8), &aes_key);

                int blocksNum = 0;
                AES_cfb128_encrypt(encryptedBytes, outBuffer, outBufferLength, &aes_key, ivDataBytes, &blocksNum, decrypt ? AES_DECRYPT : AES_ENCRYPT);

                memset(&aes_key, 0, sizeof(AES_KEY));
            }
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
        case PGPSymmetricTwofish256: {
            static dispatch_once_t twoFishInit;
            dispatch_once(&twoFishInit, ^{ Twofish_initialise(); });

            Twofish_key xkey;
            Twofish_prepare_key((uint8_t *)sessionKeyData.bytes, (int)sessionKeyData.length, &xkey);

            if (syncCFB) {
                // TODO: OpenPGP CFB Mode is different here
            } else {
                if (decrypt) {
                    // decrypt
                    NSMutableData *decryptedOutMutableData = encryptedData.mutableCopy;
                    var ciphertextBlock = [NSData dataWithData:ivData];
                    let plaintextBlock = [NSMutableData dataWithLength:blockSize];
                    for (NSUInteger index = 0; index < encryptedData.length; index += blockSize) {
                        Twofish_encrypt(&xkey, (uint8_t *)ciphertextBlock.bytes, plaintextBlock.mutableBytes);
                        ciphertextBlock = [encryptedData subdataWithRange:(NSRange){index, MIN(blockSize, decryptedOutMutableData.length - index)}];
                        [decryptedOutMutableData XORWithData:plaintextBlock index:index];
                    }
                    decryptedData = decryptedOutMutableData;
                } else {
                    // encrypt
                    NSMutableData *encryptedOutMutableData = encryptedData.mutableCopy; // input plaintext
                    var plaintextBlock = [NSData dataWithData:ivData];
                    let ciphertextBlock = [NSMutableData dataWithLength:blockSize];
                    for (NSUInteger index = 0; index < encryptedData.length; index += blockSize) {
                        Twofish_encrypt(&xkey, (uint8_t *)plaintextBlock.bytes, ciphertextBlock.mutableBytes);
                        [encryptedOutMutableData XORWithData:ciphertextBlock index:index];
                        plaintextBlock = [encryptedOutMutableData subdataWithRange:(NSRange){index, MIN(blockSize, encryptedOutMutableData.length - index)}]; // ciphertext.copy;
                    }
                    decryptedData = encryptedOutMutableData;
                }
            }

            memset(&xkey, 0, sizeof(Twofish_key));
        } break;
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
