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
#import "NSData+PGPUtils.h"
#import "PGPModificationDetectionCodePacket.h"

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
    return PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag; // 18
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = 0;

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
    NSAssert(self.version == 1, @"Require version == 1");
    
    if (!self.encryptedData)
    {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No encrypted data? try encrypt first"}];
        }
        return nil;
    }
    
    NSMutableData *bodyData = [NSMutableData data];
    // A one-octet version number.
    [bodyData appendBytes:&_version length:1];
    // Encrypted data
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

- (void) encrypt:(NSData *)literalPacketData withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    //     OpenPGP does symmetric encryption using a variant of Cipher Feedback mode (CFB mode).
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:symmetricAlgorithm];

    // The Initial Vector (IV) is specified as all zeros.
    NSMutableData *ivData = [NSMutableData dataWithLength:blockSize];
    
    // Prepare preamble
    // Instead of using an IV, OpenPGP prefixes a string of length equal to the block size of the cipher plus two to the data before it is encrypted.
    // The first block-size octets (for example, 8 octets for a 64-bit block length) are random,
    NSMutableData *prefixRandomData = [NSMutableData dataWithCapacity:blockSize];
#ifdef DEBUG
    UInt8 nonRandomBytes[8] = {0x80, 0xfa, 0x06, 0xcc, 0xe3, 0x7b, 0xa8, 0x7a};
    prefixRandomData = [[NSMutableData alloc] initWithBytes:nonRandomBytes length:8];
#else
    for (int i = 0; i < blockSize; i++) {
        UInt8 byte = arc4random_uniform(255);
        [prefixRandomData appendBytes:&byte length:1];
    }
#endif
                                      
    // and the following two octets are copies of the last two octets of the IV.
    NSMutableData *prefixRandomFullData = [NSMutableData dataWithData:prefixRandomData];
    [prefixRandomFullData appendData:[prefixRandomData subdataWithRange:(NSRange){prefixRandomData.length - 2, 2}]];

    NSLog(@"preamble %@", prefixRandomFullData);
    // Prepare MDC Packet
    NSMutableData *toMDCData = [[NSMutableData alloc] init];
    // preamble
    [toMDCData appendData:prefixRandomFullData];
    // plaintext
    [toMDCData appendData:literalPacketData];
    // and then also includes two octets of values 0xD3, 0x14 (sha length)
    UInt8 mdc_suffix[2] = {0xD3, 0x14};
    [toMDCData appendBytes:&mdc_suffix length:2];
    
    PGPModificationDetectionCodePacket *mdcPacket = [[PGPModificationDetectionCodePacket alloc] initWithData:toMDCData];
    NSError *exportMDCError = nil;
    NSData *mdcPacketData = [mdcPacket exportPacket:&exportMDCError];
    if (exportMDCError) {
        return;
    }
    
    // Finally build encrypted packet data
    // Encrypt at once (the same encrypt key) preamble + data + mdc
    NSMutableData *toEncrypt = [NSMutableData data];
    [toEncrypt appendData:prefixRandomFullData];
    [toEncrypt appendData:literalPacketData];
    [toEncrypt appendData:mdcPacketData];
    NSData *encrypted = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:symmetricAlgorithm iv:ivData];
    
    self.encryptedData = encrypted;
}

@end
