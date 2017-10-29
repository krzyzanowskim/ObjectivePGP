//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    self.encryptedData = packetBody;

    return position;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    if (!self.encryptedData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Unable to export packet. Missing encrypted data." }];
        }
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
