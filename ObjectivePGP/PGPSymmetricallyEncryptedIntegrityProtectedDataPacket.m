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
#import "PGPLiteralPacket.h"
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

- (NSData *) decryptWithSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData error:(NSError * __autoreleasing *)error
{
    NSAssert(self.encryptedData, @"Missing encrypted data to decrypt");
    NSAssert(secretKeyPacket, @"Missing secret key");
    NSAssert(!secretKeyPacket.isEncrypted, @"Decrypt secret key first");
    
    if (!self.encryptedData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Missing encrypted data"}];
        }
        return nil;
    }
    
    if (secretKeyPacket.isEncrypted) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Encrypted secret key used to decryption. Decrypt key first"}];
        }
        return nil;
    }

    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:sessionKeyAlgorithm];

    // The Initial Vector (IV) is specified as all zeros.
    NSMutableData *ivData = [NSMutableData dataWithLength:blockSize];

    NSUInteger position = 0;
    // preamble + data + mdc
    NSData *decryptedData = [PGPCryptoCFB decryptData:self.encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:sessionKeyAlgorithm iv:ivData];
    NSLog(@"decrypted\n%@",decryptedData);
    // full prefix blockSize + 2
    NSData *prefixRandomFullData = [decryptedData subdataWithRange:(NSRange){position, blockSize + 2}];
    position = position + blockSize + 2;
    
    // check if suffix match
    if (![[prefixRandomFullData subdataWithRange:(NSRange){blockSize + 2 - 4, 2}] isEqualToData:[prefixRandomFullData subdataWithRange:(NSRange){blockSize + 2 - 2, 2}]]) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Random suffix mismatch"}];
        }
        return nil;
    }
    
    // read literal packet data
    //TODO: litera OR compressed packet
    PGPLiteralPacket *literalPacket = (PGPLiteralPacket *)[PGPPacketFactory packetWithData:decryptedData offset:position];
    NSAssert([literalPacket isKindOfClass:[PGPLiteralPacket class]], @"Invalid packet, expected Literal packet");
    NSData *literalPacketData = [decryptedData subdataWithRange:(NSRange){position, literalPacket.headerData.length + literalPacket.bodyData.length}];
    position = position + literalPacket.headerData.length + literalPacket.bodyData.length;

    // mdc packet
    PGPModificationDetectionCodePacket *mdcPacket = (PGPModificationDetectionCodePacket *)[PGPPacketFactory packetWithData:decryptedData offset:position];
    NSAssert([mdcPacket isKindOfClass:[PGPModificationDetectionCodePacket class]], @"Invalid packet, expected MDC");
    
    // validation: calculate MDC hash to check if literal data is modified
    NSMutableData *toMDCData = [[NSMutableData alloc] init];
    // preamble
    [toMDCData appendData:prefixRandomFullData];
    // plaintext
    [toMDCData appendData:literalPacketData];
    // and then also includes two octets of values 0xD3, 0x14 (sha length)
    UInt8 mdc_suffix[2] = {0xD3, 0x14};
    [toMDCData appendBytes:&mdc_suffix length:2];
    
    NSData *mdcHash = [toMDCData pgpSHA1];
    if (![mdcHash isEqualToData:mdcPacket.hashData]) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"MDC validation failed"}];
        }
        return nil;
    }
    
    return literalPacket.literalRawData;
}

- (void) encrypt:(NSData *)literalPacketData withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData
{
    // OpenPGP does symmetric encryption using a variant of Cipher Feedback mode (CFB mode).
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:sessionKeyAlgorithm];

    // The Initial Vector (IV) is specified as all zeros.
    NSMutableData *ivData = [NSMutableData dataWithLength:blockSize];
    
    // Prepare preamble
    // Instead of using an IV, OpenPGP prefixes a string of length equal to the block size of the cipher plus two to the data before it is encrypted.
    // The first block-size octets (for example, 8 octets for a 64-bit block length) are random,
    NSMutableData *prefixRandomData = [NSMutableData dataWithCapacity:blockSize];

    for (int i = 0; i < blockSize; i++) {
        UInt8 byte = arc4random_uniform(255);
        [prefixRandomData appendBytes:&byte length:1];
    }
    
    // and the following two octets are copies of the last two octets of the IV.
    NSMutableData *prefixRandomFullData = [NSMutableData dataWithData:prefixRandomData];
    [prefixRandomFullData appendData:[prefixRandomData subdataWithRange:(NSRange){prefixRandomData.length - 2, 2}]];

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
    NSData *encrypted = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:sessionKeyAlgorithm iv:ivData];
    
    self.encryptedData = encrypted;
}

@end
