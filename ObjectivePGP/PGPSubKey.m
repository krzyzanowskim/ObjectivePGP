//
//  PGPSubKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPMacros.h"
#import "PGPSubKey.h"
#import "PGPPublicKeyPacket.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPSubKey

- (instancetype)initWithPacket:(PGPPacket *)packet
{
    if ((self = [super init])) {
        self.primaryKeyPacket = packet;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@",super.description, self.primaryKeyPacket.description];
}

- (PGPKeyID *)keyID {
    //note: public key packet because this is main class for public and secret class
    let primaryKeyPacket = PGPCast(self.primaryKeyPacket, PGPPublicKeyPacket);
    NSCAssert(primaryKeyPacket, @"Invalid packet");
    return [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
}

- (NSArray<PGPPacket *> *)allPackets {
    let arr = [NSMutableArray<PGPPacket *> arrayWithObject:self.primaryKeyPacket];

    if (self.revocationSignature) {
        [arr addObject:self.revocationSignature];
    }

    if (self.bindingSignature) {
        [arr addObject:self.bindingSignature];
    }

    return arr;
}

@end

NS_ASSUME_NONNULL_END
