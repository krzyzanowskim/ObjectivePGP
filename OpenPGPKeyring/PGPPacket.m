//
//  PGPPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@implementation PGPPacket

- (instancetype)initWithHeader:(NSData *)headerData body:(NSData *)bodyData
{
    if (self = [self init]) {
        self.headerLength = headerData.length;
        [self parsePacketBody:bodyData];
    }
    return self;
}


- (void) parsePacketBody:(NSData *)packetBody
{
    self.bodyLength = packetBody.length;
}

#pragma mark - Packet header

// 4.2.  Packet Headers
/**
 *  Parse header
 *
 *  @param headerData header data
 *
 *  @return Actual header data
 */
+ (NSData *) parsePacketHeader:(NSData *)headerData bodyLength:(UInt32 *)bodyLength packetTag:(PGPPacketTag *)tag
{
    UInt8 *headerBytes = (UInt8 *)[headerData subdataWithRange:NSMakeRange(0, 1)].bytes;
    UInt8 headerByte = headerBytes[0];

    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);


    if (!isPGPHeader) {
        return NO;
    }

    NSUInteger headerLength = 0;
    if (isNewFormat) {
        headerLength = [self parseNewFormatHeaderPacket:headerData bodyLength:bodyLength packetTag:tag];
    } else {
        headerLength = [self parseOldFormatHeaderPacket:headerData bodyLength:bodyLength packetTag:tag];
    }

    return [headerData subdataWithRange:(NSRange){0,headerLength}];
}

/**
 *  4.2.  Packet Headers
 *
 *  @param packetData Packet header
 *
 *  @return Header length
 */
+ (NSUInteger) parseNewFormatHeaderPacket:(NSData *)headerData bodyLength:(UInt32 *)length packetTag:(PGPPacketTag *)tag
{
    NSParameterAssert(headerData);

    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte length:1];
    // Bits 5-0 -- packet tag
    UInt8 packetTag = (headerByte << 2);
    packetTag = (packetTag >> 2);
    *tag = packetTag;

    // body length
    BOOL isPartialBodyLength = NO;
    UInt32 bodyLength        = 0;
    NSInteger headerLength   = 2;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(1, 5)].bytes;

    UInt8 firstOctet  = lengthOctets[0];
    UInt8 secondOctet = lengthOctets[1];
    UInt8 thirdOctet  = lengthOctets[2];
    UInt8 fourthOctet = lengthOctets[3];
    UInt8 fifthOctet  = lengthOctets[4];

    if (firstOctet < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        bodyLength   = firstOctet;
        headerLength = 1 + 1;
    } else if (firstOctet >= 192 && firstOctet <= 223) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        bodyLength   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        bodyLength   = CFSwapInt16BigToHost(bodyLength);
        headerLength = 1 + 2;
    } else if (firstOctet >= 223 && firstOctet < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        UInt32 partianBodyLength = firstOctet << (firstOctet & 0x1F);
        bodyLength               = partianBodyLength;
        headerLength             = 1 + 1;
        isPartialBodyLength      = YES;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        bodyLength   = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
        bodyLength   = CFSwapInt32BigToHost(bodyLength);
        headerLength = 1 + 5;
    }
    *length = bodyLength;

    NSAssert(bodyLength > 0, @"The packet is of indeterminate length");

    return headerLength;
}

// 4.2.  Packet Headers
+ (NSUInteger) parseOldFormatHeaderPacket:(NSData *)headerData bodyLength:(UInt32 *)length packetTag:(PGPPacketTag *)tag
{
    NSParameterAssert(headerData);

    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte length:1];
    //  Bits 5-2 -- packet tag
    UInt8 packetTag = (headerByte << 2);
    packetTag = (packetTag >> 4);
    *tag = packetTag;
    //  Bits 1-0 -- length-type
    UInt8 bodyLengthType = (headerByte << 6);
    bodyLengthType = bodyLengthType >> 6;

    NSUInteger headerLength = 1;
    UInt32 bodyLength       = 0;
    switch (bodyLengthType) {
        case 0:
        {
            NSRange range = (NSRange) {1,1};
            [headerData getBytes:&bodyLength range:range];
            headerLength = 1 + range.length;
        }
            break;
        case 1:
        {
            NSRange range = (NSRange) {1,2};
            [headerData getBytes:&bodyLength range:range];
            bodyLength = CFSwapInt16BigToHost(bodyLength);
            headerLength = 1 + range.length;
        }
            break;
        case 2:
        {
            NSRange range = (NSRange) {1,4};
            [headerData getBytes:&bodyLength range:range];
            bodyLength = CFSwapInt32BigToHost(bodyLength);
            headerLength = 1 + range.length;
        }
            break;
        case 3:
        {
            //TODO: The packet is of indeterminate length.
            headerLength = 1;
        }
            break;

        default:
            break;
    }

    NSAssert(bodyLength > 0, @"The packet is of indeterminate length");
    *length = bodyLength;
    
    return headerLength;
}


@end
