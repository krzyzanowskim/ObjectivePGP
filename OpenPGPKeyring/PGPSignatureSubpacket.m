//
//  PGPSignatureSubPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignatureSubpacket.h"

@implementation PGPSignatureSubpacket

- (instancetype) initWithBody:(NSData *)packetBody type:(PGPSignatureSubpacketType)type
{
    if (self = [self init]) {
        [self parseSubpacketBody:packetBody];
        self->_type = type;
    }
    return self;
}

/**
 *  5.2.3.1.  Signature Subpacket Specification
 *
 *  @param packetBody A single subpacket body data.
 */
- (void) parseSubpacketBody:(NSData *)packetBody
{
    //TODO: parse subpacket
}

+ (PGPSignatureSubpacketType) parseSubpacketHeader:(NSData *)headerData headerLength:(UInt32 *)headerLength subpacketLength:(UInt32 *)subpacketLen
{
    NSUInteger position     = 0;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(position, MIN(5,headerData.length))].bytes;

    UInt8 firstOctet  = lengthOctets[0];
    UInt8 secondOctet = lengthOctets[1];
    UInt8 thirdOctet  = lengthOctets[2];
    UInt8 fourthOctet = lengthOctets[3];
    UInt8 fifthOctet  = lengthOctets[4];

    if (firstOctet < 192) {
        // subpacketLen = 1st_octet;
        *subpacketLen   = firstOctet;
        *headerLength = 1 ;
    } else if (firstOctet >= 192 && firstOctet < 255) {
        // subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        *subpacketLen   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        *headerLength = 2;
    } else if (firstOctet == 255) {
        // subpacketLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //                (4th_octet << 8)  | 5th_octet
        *subpacketLen   = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
        *headerLength = 5;
    }
    position = position + *headerLength;

    //TODO: Bit 7 of the subpacket type is the "critical" bit.
    PGPSignatureSubpacketType subpacketType = 0;
    [headerData getBytes:&subpacketType range:(NSRange){position, 1}];
    return subpacketType;
}

@end
