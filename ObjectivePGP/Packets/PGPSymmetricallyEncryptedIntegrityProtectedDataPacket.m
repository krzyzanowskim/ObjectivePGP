//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "NSData+PGPUtils.h"
#import "PGPPacket+Private.h"
#import "PGPCompressedPacket.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"
#import "PGPLiteralPacket.h"
#import "PGPModificationDetectionCodePacket.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPPartialKey.h"
#import "PGPRSA.h"
#import "PGPSecretKeyPacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

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

NS_ASSUME_NONNULL_BEGIN

@interface PGPSymmetricallyEncryptedIntegrityProtectedDataPacket ()

@property (nonatomic, readwrite) NSUInteger version;

@end


@implementation PGPSymmetricallyEncryptedIntegrityProtectedDataPacket

- (instancetype)init {
    if (self = [super init]) {
        _version = 1;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag; // 18
}

- (NSArray<PGPPacket *> *)readPacketsFromData:(NSData *)data offset:(NSUInteger)offsetPosition mdcLength:(nullable NSUInteger *)mdcLength {
    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    if (mdcLength) { *mdcLength = 0; }
    NSInteger offset = offsetPosition;
    NSUInteger consumedBytes = 0;
    while (offset < (NSInteger)data.length) {
        let packet = [PGPPacketFactory packetWithData:data offset:offset consumedBytes:&consumedBytes];
        if (packet) {
            [accumulatedPackets addObject:packet];
            if (packet.tag != PGPModificationDetectionCodePacketTag) {
                if (mdcLength) {
                    *mdcLength += consumedBytes;
                }
            }

            // A compressed Packet contains more packets
            let _Nullable compressedPacket = PGPCast(packet, PGPCompressedPacket);
            if (compressedPacket) {
                // TODO: Compression should be moved outside, be more generic to handle compressed packet from anywhere
                let uncompressedPackets = [self readPacketsFromData:compressedPacket.decompressedData offset:0 mdcLength:nil];
                [accumulatedPackets addObjectsFromArray:uncompressedPackets ?: @[]];
            }

            if (packet.indeterminateLength && accumulatedPackets.count > 0 && PGPCast(accumulatedPackets.firstObject, PGPCompressedPacket)) {
                // FIXME: substract size of PGPModificationDetectionCodePacket in this very special case - TODO: fix this
                offset -= 22;
                if (mdcLength) {
                    *mdcLength -= 22;
                }
            }
        }

        // corrupted data. Move by one byte in hope we find some packet there, or EOF.
        if (consumedBytes == 0) {
            offset++;
        }

        offset += consumedBytes;
    }
    return accumulatedPackets;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
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

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    NSAssert(self.encryptedData, @"No encrypted data?");
    NSAssert(self.version == 1, @"Require version == 1");

    if (!self.encryptedData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"No encrypted data? try encrypt first" }];
        }
        return nil;
    }

    let bodyData = [NSMutableData data];
    // A one-octet version number.
    [bodyData appendBytes:&_version length:1];
    // Encrypted data
    [bodyData appendData:self.encryptedData];

    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return bodyData;
    }];
}

// return array of packets
- (NSArray<PGPPacket *> *)decryptWithSessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData error:(NSError * __autoreleasing _Nullable *)error {
    NSAssert(self.encryptedData, @"Missing encrypted data to decrypt");

    if (!self.encryptedData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Missing data to decrypt." }];
        }
        return @[];
    }

    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:sessionKeyAlgorithm];

    // The Initial Vector (IV) is specified as all zeros.
    let ivData = [NSMutableData dataWithLength:blockSize];

    NSUInteger position = 0;
    // preamble + data + mdc
    let decryptedData = [PGPCryptoCFB decryptData:self.encryptedData sessionKeyData:sessionKeyData symmetricAlgorithm:sessionKeyAlgorithm iv:ivData syncCFB:NO];
    // full prefix blockSize + 2
    let prefixRandomFullData = [decryptedData subdataWithRange:(NSRange){position, blockSize + 2}];
    position = position + blockSize + 2;

    // check if suffix match
    if (!PGPEqualObjects([prefixRandomFullData subdataWithRange:(NSRange){blockSize + 2 - 4, 2}] ,[prefixRandomFullData subdataWithRange:(NSRange){blockSize + 2 - 2, 2}])) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Validation failed. Random suffix mismatch." }];
        }
        return @[];
    }

    NSUInteger mdcLength = 0;
    let packets = [self readPacketsFromData:decryptedData offset:position mdcLength:&mdcLength];

    let _Nullable lastPacket = PGPCast(packets.lastObject, PGPPacket);
    if (!lastPacket || lastPacket.tag != PGPModificationDetectionCodePacketTag) {
        // No Integrity Protected found, can't verify. Guess it's modified.
        // if (checkIsContentModified) { *checkIsContentModified = YES; }
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Content modification detected." }];
        }
        return @[];
    }

    let _Nullable mdcPacket = PGPCast(lastPacket, PGPModificationDetectionCodePacket);
    if (!mdcPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Unexpected sequence of data (missing MDC)." }];
        }
        return @[];
    }

    let toMDCData = [[NSMutableData alloc] init];
    // preamble
    [toMDCData appendData:prefixRandomFullData];
    // validation: calculate MDC hash to check if literal data is modified
    [toMDCData appendData:[decryptedData subdataWithRange:(NSRange){position, mdcLength}]];

    // and then also includes two octets of values 0xD3, 0x14 (sha length)
    UInt8 mdc_suffix[2] = {0xD3, 0x14};
    [toMDCData appendBytes:&mdc_suffix length:2];

    let mdcHash = [toMDCData pgp_SHA1];
    if (!mdcPacket || !PGPEqualObjects(mdcHash,mdcPacket.hashData)) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Validation failed. Content modification detected." }];
        }
        return @[];
    }

    return [packets subarrayWithRange:(NSRange){0, packets.count - 1}];
}

- (BOOL)encrypt:(NSData *)literalPacketData symmetricAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData error:(NSError * __autoreleasing _Nullable *)error {
    @autoreleasepool {
        // OpenPGP does symmetric encryption using a variant of Cipher Feedback mode (CFB mode).
        NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:sessionKeyAlgorithm];

        // The Initial Vector (IV) is specified as all zeros.
        let ivData = [NSMutableData dataWithLength:blockSize];

        // Prepare preamble
        // Instead of using an IV, OpenPGP prefixes a string of length equal to the block size of the cipher plus two to the data before it is encrypted.
        // The first block-size octets (for example, 8 octets for a 64-bit block length) are random,
        uint8_t buf[blockSize];
        if (SecRandomCopyBytes(kSecRandomDefault, blockSize, buf) == -1) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Encryption failed. Cannot prepare random data."}];
            }
            return NO;
        }
        let prefixRandomData = [NSMutableData dataWithBytes:buf length:blockSize];

        // and the following two octets are copies of the last two octets of the IV.
        let prefixRandomFullData = [NSMutableData dataWithData:prefixRandomData];
        [prefixRandomFullData appendData:[prefixRandomData subdataWithRange:(NSRange){prefixRandomData.length - 2, 2}]];

        // Prepare MDC Packet
        let toMDCData = [[NSMutableData alloc] init];
        // preamble
        [toMDCData appendData:prefixRandomFullData];
        // plaintext
        [toMDCData appendData:literalPacketData];
        // and then also includes two octets of values 0xD3, 0x14 (sha length)
        UInt8 mdc_suffix[2] = {0xD3, 0x14};
        [toMDCData appendBytes:&mdc_suffix length:2];

        let mdcPacket = [[PGPModificationDetectionCodePacket alloc] initWithData:toMDCData];
        let _Nullable mdcPacketData = [mdcPacket export:error];
        if (!mdcPacketData || (error && *error)) {
            return NO;
        }

        // Finally build encrypted packet data
        // Encrypt at once (the same encrypt key) preamble + data + mdc
        let toEncrypt = [NSMutableData data];
        [toEncrypt appendData:prefixRandomFullData];
        [toEncrypt appendData:literalPacketData];
        [toEncrypt appendData:mdcPacketData];
        let encrypted = [PGPCryptoCFB encryptData:toEncrypt sessionKeyData:sessionKeyData symmetricAlgorithm:sessionKeyAlgorithm iv:ivData syncCFB:NO];

        self.encryptedData = encrypted;
        return YES;
    }
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToPGPSymmetricallyEncryptedIntegrityProtectedDataPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToPGPSymmetricallyEncryptedIntegrityProtectedDataPacket:(PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *)packet {
    return self.version == packet.version;
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPSymmetricallyEncryptedIntegrityProtectedDataPacket);
    if (!duplicate) {
        return nil;
    }

    duplicate.version = self.version;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
