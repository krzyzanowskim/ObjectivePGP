//
//  PGPTrustPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTrustPacket.h"

@interface PGPTrustPacket ()
@property (strong, readwrite) NSData *data;
@end

@implementation PGPTrustPacket

- (PGPPacketTag)tag
{
    return PGPTrustPacketTag;
}

- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // 5.10.  Trust Packet (Tag 12)
    // The format of Trust packets is defined by a given implementation.
    self.data = packetBody;
    position = position + self.data.length;
    return position;
}


- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    //TODO: export trust packet
    //  (1 octet "level" (depth), 1 octet of trust amount)
    return [self.data copy];
}

@end
