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

//TODO: handle image subtype. Somehow it's broken, so not supported.
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    position = position + packetBody.length;
    return position;
//    while (position < position + packetBody.length) {
//        UInt8 lengthLength = 0;
//        UInt8 *lengthOctets = (UInt8 *)[packetBody subdataWithRange:(NSRange){position, 5}].bytes;
//        UInt8 subpacketLength   = lengthOctets[0];
//        
//        if (lengthOctets[0] < 192) {
//            // 4.2.2.1.  One-Octet Length
//            // bodyLen = 1st_octet;
//            subpacketLength   = lengthOctets[0];
//            lengthLength = 1;
//        } else if (lengthOctets[0] >= 192 && lengthOctets[0] <= 223) {
//            // 4.2.2.2.  Two-Octet Lengths
//            // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
//            subpacketLength   = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
//            lengthLength = 2;
//        } else {
//            // 4.2.2.3.  Five-Octet Length
//            // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
//            //           (4th_octet << 8)  | 5th_octet
//            subpacketLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
//            lengthLength = 5;
//        }
//        NSLog(@"PGPUserAttributePacket subpacketLength %@ (%@)",@(subpacketLength), @(lengthLength));
//        position = position + lengthLength;
//
//        UInt8 subpacketType = 0;
//        [packetBody getBytes:&subpacketType range:(NSRange){position, 1}];
//        position = position + 1;
//
////        PGPUserAttributeSubpacket *subpacket = [[PGPUserAttributeSubpacket alloc] init];
////        subpacket.type = subpacketType;
////        subpacket.valueData = [packetBody subdataWithRange:(NSRange){position, subpacketLength}];
////        position = position + subpacketLength;
////
////        self.subpackets = [self.subpackets arrayByAddingObject:subpacket];
//    }

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
