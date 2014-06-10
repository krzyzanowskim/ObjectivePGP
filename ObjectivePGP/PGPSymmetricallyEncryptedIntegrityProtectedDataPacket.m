//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPKey.h"
#import "PGPPublicKeyRSA.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"

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

@implementation PGPSymmetricallyEncryptedIntegrityProtectedDataPacket

- (instancetype)init
{
    if (self = [super init]) {
        self.version = 1;
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // The content of an encrypted data packet is more OpenPGP packets
    // once decrypted, so recursively handle them
    [packetBody getBytes:&_version range:(NSRange){position, 1}];
    position = position + 1;

    // - Encrypted data, the output of the selected symmetric-key cipher
    // operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
    self.encryptedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    position = position + self.encryptedData.length;
    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSAssert(self.encryptedData, @"No encrypted data?");
    if (!self.encryptedData)
    {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No encrypted data? try encrypt first"}];
        }
        return nil;
    }
    
    NSMutableData *bodyData = [NSMutableData data];
    [bodyData appendBytes:&_version length:1];
    [bodyData appendData:self.encryptedData];
    
    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];
    return [data copy];
}


// returns decrypted data
//- (NSData *) decrypt:(PGPSecretKeyPacket *)secretKeyPacket
//{
//    return [PGPPublicKeyRSA privateDecrypt:self.encryptedData withSecretKeyPacket:secretKeyPacket];
//}

- (void) encrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    switch (publicKeyPacket.publicKeyAlgorithm) {
        case PGPPublicKeyAlgorithmRSA:
        case PGPPublicKeyAlgorithmRSAEncryptOnly:
        case PGPPublicKeyAlgorithmRSASignOnly:
        {
            // ivData is block size long with zeroes here
            NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];
            UInt8 *zeroes = calloc(blockSize, sizeof(UInt8));
            NSMutableData *ivData = [NSMutableData dataWithBytes:zeroes length:blockSize];
            free(zeroes);
            
            
            NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:symmetricAlgorithm];
            
            // Seems IV is encrypted (cant find it in docs)
            //CAST_ecb_encrypt(in, out, crypt->encrypt_key, CAST_ENCRYPT);
            
            const void *encryptedBytes = ivData.bytes;
            NSUInteger outButterLength = ivData.length;
            UInt8 *outBuffer = calloc(outButterLength, sizeof(UInt8));
            // initialize
            CAST_KEY *encrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(encrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
            
            CAST_KEY *decrypt_key = calloc(1, sizeof(CAST_KEY));
            CAST_set_key(decrypt_key, (unsigned int)keySize, sessionKeyData.bytes);
            
            // see __ops_decrypt_init block_encrypt siv,civ,iv comments. siv is needed for weird v3 resync,
            // wtf civ ???
            // CAST_ecb_encrypt(in, out, encrypt_key, CAST_ENCRYPT);
            
            CAST_ecb_encrypt(encryptedBytes, outBuffer, encrypt_key, CAST_ENCRYPT);
            NSData *ivEncryptedData = [NSData dataWithBytes:outBuffer length:outButterLength];
            NSLog(@"%@",ivEncryptedData);
            if (encrypt_key) free(encrypt_key);
            if (decrypt_key) free(decrypt_key);
            
            NSData *encryptedData = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData];
            self.encryptedData = encryptedData;
        }
            break;
        default:
            //TODO: add algorithms
            [NSException raise:@"PGPNotSupported" format:@"Algorith not supported"];
            break;
    }
}

@end
