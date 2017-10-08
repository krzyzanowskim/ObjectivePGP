//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Parse only

#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"
#import "PGPPublicKeyPacket.h"
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

@implementation PGPSymmetricallyEncryptedDataPacket

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    self.encryptedData = packetBody;

    return position;
}

- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    NSAssert(self.encryptedData, @"Need encrypted data, use PGPSymmetricallyEncryptedIntegrityProtectedDataPacket instead");
    if (!self.encryptedData) {
        return nil;
    }

    return self.encryptedData;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToSymmetricallyEncryptedDataPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToSymmetricallyEncryptedDataPacket:(PGPSymmetricallyEncryptedDataPacket *)packet {
    return PGPEqualObjects(self.encryptedData, packet.encryptedData);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.encryptedData.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPSymmetricallyEncryptedDataPacket);
    if (!duplicate) {
        return nil;
    }
    duplicate.encryptedData = self.encryptedData;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
