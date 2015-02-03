//
//  PGPUser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUser.h"

@implementation PGPUser

- (instancetype)initWithPacket:(PGPUserIDPacket *)packet
{
    if (self = [super init]) {
        NSAssert([packet isKindOfClass:[PGPUserIDPacket class]], @"Invalid class");
        _packet = packet;
        _userID = packet.userID;
    }
    return self;
}

@end
