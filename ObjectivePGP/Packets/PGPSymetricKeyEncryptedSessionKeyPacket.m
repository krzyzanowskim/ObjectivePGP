//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

// 5.3.  Symmetric-Key Encrypted Session Key Packets (Tag 3)

#import "PGPSymetricKeyEncryptedSessionKeyPacket.h"
#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPCryptoUtils.h"
#import "PGPFingerprint.h"
#import "PGPKeyID.h"
#import "PGPS2K.h"
#import "PGPMPI.h"
#import "PGPPKCSEme.h"
#import "PGPPublicKeyPacket.h"
#import "PGPRSA.h"
#import "PGPSecretKeyPacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPSymetricKeyEncryptedSessionKeyPacket

- (instancetype)init {
    if (self = [super init]) {
        _version = 4;
        _symmetricAlgorithm = PGPSymmetricPlaintext;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPSymetricKeyEncryptedSessionKeyPacketTag; // 3
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // A one-octet number giving the version number of the packet type. The currently defined value for packet version is 3.
    [packetBody getBytes:&_version range:(NSRange){position, 1}];
    NSAssert(self.version == 4, @"The currently defined value for packet version is 4");
    position = position + 1;

    // A one-octet number describing the symmetric algorithm used.
    [packetBody getBytes:&_symmetricAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // A string-to-key (S2K) specifier, length as defined above.
    NSUInteger s2kParsedLength = 0;
    self.s2k = [PGPS2K S2KFromData:packetBody atPosition:position length:&s2kParsedLength];
    position = position + s2kParsedLength;

    if (packetBody.length > position) {
        // Optionally, the encrypted session key itself, which is decrypted with the string-to-key object.
        self.encryptedSessionKey = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    }

    return position;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    let bodyData = [NSMutableData data];

    [bodyData appendBytes:&_version length:1]; // 1
    [bodyData appendBytes:&_symmetricAlgorithm length:1]; // 1
    [bodyData pgp_appendData:[self.s2k export:error]];
    [bodyData pgp_appendData:self.encryptedSessionKey];
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return bodyData;
    }];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToSessionKeyPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToSessionKeyPacket:(PGPSymetricKeyEncryptedSessionKeyPacket *)packet {
    return self.version == packet.version &&
           self.symmetricAlgorithm == packet.symmetricAlgorithm &&
           PGPEqualObjects(self.s2k, packet.s2k) &&
           self.encryptedSessionKey == packet.encryptedSessionKey;
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.version;
    result = prime * result + self.symmetricAlgorithm;
    result = prime * result + self.s2k.hash;
    result = prime * result + self.encryptedSessionKey.hash;
    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([super copyWithZone:zone], PGPSymetricKeyEncryptedSessionKeyPacket);
    PGPAssertClass(duplicate, PGPSymetricKeyEncryptedSessionKeyPacket);
    duplicate.version = self.version;
    duplicate.symmetricAlgorithm = self.symmetricAlgorithm;
    duplicate.s2k = self.s2k;
    duplicate.encryptedSessionKey = self.encryptedSessionKey;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
