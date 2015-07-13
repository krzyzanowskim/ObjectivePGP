//
//  PGPSubKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSubKey.h"
#import "PGPPublicKeyPacket.h"

@implementation PGPSubKey

- (instancetype) initWithPacket:(PGPPacket *)packet
{
    if (self = [self init]) {
        self.primaryKeyPacket = packet;
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], [self.primaryKeyPacket description]];
}

- (PGPKeyID *)keyID
{
    //note: public key packet because this is main class for public and secret class
    PGPPublicKeyPacket *primaryKeyPacket = (PGPPublicKeyPacket *)self.primaryKeyPacket;
    PGPKeyID *keyID = [[PGPKeyID alloc] initWithFingerprint:primaryKeyPacket.fingerprint];
    return keyID;
}

- (NSArray *) allPackets
{
    NSMutableArray *arr = [NSMutableArray array];

    [arr addObject:self.primaryKeyPacket];

    if (self.revocationSignature) {
        [arr addObject:self.revocationSignature];
    }

    if (self.bindingSignature) {
        [arr addObject:self.bindingSignature];
    }

    return [arr copy];
}
@end
