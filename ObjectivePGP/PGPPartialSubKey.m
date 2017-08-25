//
//  PGPPartialSubKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPartialSubKey.h"
#import "PGPMacros.h"
#import "PGPPublicKeyPacket.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPartialSubKey

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets {
    if ((self = [super initWithPackets:@[]])) {
        self.primaryKeyPacket = packets.firstObject;
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

    if (self.revocationSignature) {
        [arr addObject:PGPNN(self.revocationSignature)];
    }

    if (self.bindingSignature) {
        [arr addObject:PGPNN(self.bindingSignature)];
    }

    return arr;
}

@end

NS_ASSUME_NONNULL_END
