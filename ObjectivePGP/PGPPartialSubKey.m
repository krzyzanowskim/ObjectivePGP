//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPartialSubKey.h"
#import "PGPPartialSubKey+Private.h"
#import "PGPPartialKey.h"
#import "PGPPartialKey+Private.h"
#import "PGPPublicKeyPacket.h"
#import "PGPFoundation.h"
#import "PGPKeyID.h"
#import "PGPMacros+Private.h"
#import "NSArray+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPartialSubKey

@dynamic revocationSignature;

- (instancetype)initWithPacket:(PGPPacket *)packet {
    if ((self = [super initWithPackets:@[]])) {
        self.primaryKeyPacket = packet;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", super.description, self.primaryKeyPacket.description];
}

- (PGPKeyID *)keyID {
    // note: public key packet because this is main class for public and secret class
    let primaryKeyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
    NSCAssert(primaryKeyPacket, @"Invalid packet");
    return [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
}

- (NSArray<PGPPacket *> *)allPackets {
    let arr = [NSMutableArray<PGPPacket *> arrayWithObject:self.primaryKeyPacket];
    [arr pgp_addObject:PGPCast(self.revocationSignature, PGPPacket)];
    [arr pgp_addObject:PGPCast(self.bindingSignature, PGPPacket)];
    return arr;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let _Nullable subKey = PGPCast([super copyWithZone:zone], PGPPartialSubKey);
    if (!subKey) {
        return nil;
    }
    subKey.primaryKeyPacket = self.primaryKeyPacket;
    subKey.bindingSignature = self.bindingSignature;
    subKey.revocationSignature = self.revocationSignature;
    return subKey;
}

@end

NS_ASSUME_NONNULL_END
