//
//  PGPUserAttributePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"

@implementation PGPUserAttributePacket

- (PGPPacketTag)tag
{
    return PGPUserAttributePacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    while (position < position + packetBody.length) {
        UInt8 subpacketLength = 0;
        [packetBody getBytes:&subpacketLength range:(NSRange){position, 1}];
        position = position + 1;

        UInt8 subpacketType = 0;
        [packetBody getBytes:&subpacketType range:(NSRange){position, 1}];
        position = position + 1;

        PGPUserAttributeSubpacket *subpacket = [[PGPUserAttributeSubpacket alloc] init];
        subpacket.type = subpacketType;
        subpacket.valueData = [packetBody subdataWithRange:(NSRange){position, subpacketLength}];
        position = position + subpacketLength;

        self.subpackets = [self.subpackets arrayByAddingObject:subpacket];
    }

    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    //TODO: export
    return nil;
}

- (NSUInteger)hash
{
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.tag;
    result = prime * result + [_subpackets hash];

    return result;
}

@end
