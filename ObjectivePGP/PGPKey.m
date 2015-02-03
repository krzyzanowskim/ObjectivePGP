//
//  PGPKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//  see 11.1.Transferable Public Keys, 11.2.Transferable Secret Keys
//

#import "PGPKey.h"
#import "PGPFunctions.h"

@implementation PGPKey

- (instancetype)initWithPacket:(PGPPublicKeyPacket *)packet
{
    if (self = [super init]) {
        NSAssert([packet isKindOfClass:[PGPPublicKeyPacket class]], @"Invalid class");
        [self calculateFingerprint];
        _packet = packet;
    }
    return self;
}

- (void) calculateFingerprint
{
    // build key as old style packet
    
    //_hashedData = [keyData pgp_SHA1];
}

@end
