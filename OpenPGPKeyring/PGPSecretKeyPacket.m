//
//  PGPSecretKeyPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A Secret-Key packet contains all the information that is found in a
//  Public-Key packet, including the public-key material, but also
//  includes the secret-key material after all the public-key fields.

#import "PGPSecretKeyPacket.h"

@implementation PGPSecretKeyPacket

- (PGPPacketTag)tag
{
    return PGPSecretKeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody
{
    NSUInteger position = [super parsePacketBody:packetBody];
    //  5.5.3.  Secret-Key Packet Formats

    return position;
}

@end
