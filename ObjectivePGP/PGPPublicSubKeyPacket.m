//
//  PGPPublicSubKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicSubKeyPacket.h"

@implementation PGPPublicSubKeyPacket

- (PGPPacketTag)tag
{
    return PGPPublicSubkeyPacketTag;
}

@end
