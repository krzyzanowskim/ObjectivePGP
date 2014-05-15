//
//  PGPSecretSubKeyPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
//  Key packet and has exactly the same format.


#import "PGPSecretSubKeyPacket.h"

@implementation PGPSecretSubKeyPacket

- (PGPPacketTag)tag
{
    return PGPSecretSubkeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    return [super parsePacketBody:packetBody error:error];
}

@end
