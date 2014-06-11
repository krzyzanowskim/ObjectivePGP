//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPCryptoUtils.h"
#import "PGPCryptoCFB.h"

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

@implementation PGPSymmetricallyEncryptedDataPacket

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    
    return position;
}

- (void) encrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    NSMutableData *data = [NSMutableData data];
    
    // The Initial Vector (IV) is specified as all zeros.
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:symmetricAlgorithm];
    NSMutableData *ivData = [NSMutableData dataWithLength:blockSize];
    
    // Instead of using an IV, OpenPGP prefixes a string of length equal to the block size of the cipher plus two to the data before it is encrypted.
    NSMutableData *prefixData = [NSMutableData dataWithCapacity:blockSize + 2];
    // The first block-size octets (for example, 8 octets for a 64-bit block length) are random,
    for (int i = 0; i < blockSize; i++) {
        UInt8 b = arc4random_uniform(126) + 1;
        [prefixData appendBytes:&b length:1];
    }
    // and the following two octets are copies of the last two octets of the IV.
    [prefixData appendData:[prefixData subdataWithRange:(NSRange){prefixData.length - 2, 2}]];
    
    // write encrypted preamble CFB
    CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
    CAST_set_key(encrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
    CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
    CAST_set_key(decrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
    UInt8 *outBuf = calloc(ivData.length, sizeof(UInt8));
    CAST_ecb_encrypt(ivData.bytes, outBuf, encrypt_key, CAST_ENCRYPT);
    NSData *ivEncryptedData = [NSData dataWithBytes:&outBuf length:ivData.length];
    
    NSData *part = [PGPCryptoCFB encryptData:ivEncryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData];
    [data appendData:part];
    
    
    // write data CFB
    NSData *part = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData];
    
    // write MDC CFB
    
    // After encrypting the first block-size-plus-two octets, the CFB state is resynchronized.
    // The last block-size octets of ciphertext are passed through the cipher and the block boundary is reset.
    
//     OpenPGP does symmetric encryption using a variant of Cipher Feedback mode (CFB mode).
//     13.9.  OpenPGP CFB Mode
//    
//    // 1.  The feedback register (FR) is set to the IV, which is all zeros.
//    NSMutableData *FR = [NSMutableData dataWithData:ivData];
//    
//    // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the encryption of an all-zero value.
//    CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
//    CAST_set_key(encrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
//    CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
//    CAST_set_key(decrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
//    UInt8 *outBuf = calloc(ivData.length, sizeof(UInt8));
//    CAST_ecb_encrypt(ivData.bytes, outBuf, encrypt_key, CAST_ENCRYPT);
//    
//    NSData *ivEncryptedData = [NSData dataWithBytes:&outBuf length:ivData.length];
//
//    // 3.  FRE is xored with the first BS octets of random data prefixed to
//    // the plaintext to produce C[1] through C[BS], the first BS octets
//    // of ciphertext.
}

@end
