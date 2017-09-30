//
//  PGPUserAttributePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPFoundation.h"
#import "PGPMacros+Private.h"

@implementation PGPUserAttributePacket

- (PGPPacketTag)tag {
    return PGPUserAttributePacketTag;
}

// FIXME: handle image subtype. Somehow it's broken, so not supported.
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
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

- (NSData *)export:(NSError *__autoreleasing *)error {
    // TODO: export
    return nil;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToAttributePacket:other];
    }
    return NO;
}

- (BOOL)isEqualToAttributePacket:(PGPUserAttributePacket *)packet {
    return PGPEqualObjects(self.subpackets,packet.subpackets);
}

- (NSUInteger)hash {
    NSUInteger result = 1;
    result = 31 * result + self.subpackets.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable copy = PGPCast([super copyWithZone:zone], PGPUserAttributePacket);
    if (!copy) {
        return nil;
    }
    copy.subpackets = [[NSArray alloc] initWithArray:self.subpackets copyItems:YES];
    return copy;
}


@end
