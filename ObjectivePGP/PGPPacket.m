//
//  PGPPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "NSData+PGPUtils.h"

@interface PGPPacket ()
@property (copy, readwrite) NSData *headerData;
@property (copy, readwrite) NSData *bodyData;
@end

@implementation PGPPacket

- (instancetype)initWithHeader:(NSData *)headerData body:(NSData *)bodyData
{
    if (self = [self init]) {
        NSError *error = nil;
        self.headerData = headerData;
        self.bodyData = bodyData;
        [self parsePacketBody:self.bodyData error:&error];
        if (error) {
            return nil;
        }
    }
    return self;
}


- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSAssert(packetBody.length == self.bodyData.length, @"length mismach");
    return 0;
}

- (NSData *) export:(NSError *__autoreleasing *)error
{
    [NSException raise:@"MissingExportMethod" format:@"export: selector not overriden"];
    return nil;
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
    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte range:(NSRange){0,1}];

    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);


    if (!isPGPHeader) {
        return nil;
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

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(1, MIN(5, headerData.length))].bytes;
    UInt8 firstOctet  = lengthOctets[0];

    if (lengthOctets[0] < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        bodyLength   = lengthOctets[0];
        headerLength = 1 + 1;
    } else if (lengthOctets[0] >= 192 && lengthOctets[0] <= 223) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        bodyLength   = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
        bodyLength   = CFSwapInt16BigToHost(bodyLength);
        headerLength = 1 + 2;
    } else if (lengthOctets[0] >= 223 && lengthOctets[0] < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        UInt32 partianBodyLength = lengthOctets[0] << (lengthOctets[0] & 0x1F);
        bodyLength               = partianBodyLength;
        headerLength             = 1 + 1;
        isPartialBodyLength      = YES;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        bodyLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
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
            UInt16 bLen = 0;
            NSRange range = (NSRange) {1,2};
            [headerData getBytes:&bLen range:range];
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            bodyLength = CFSwapInt16BigToHost(bLen);
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

- (NSData *) buildHeaderData:(NSData *)bodyData
{
    //TODO: check all formats, untested
    //4.2.2.  New Format Packet Lengths
    NSMutableData *data = [NSMutableData data];

    // Bit 7 -- Always one
    // Bit 6 -- New packet format if set
    UInt8 packetTag = PGPHeaderPacketTagAllwaysSet | PGPHeaderPacketTagNewFormat;

    // Bits 5-0 -- packet tag
    packetTag |= self.tag;

    // write ptag
    [data appendBytes:&packetTag length:1];

    // write length octets
    UInt64 bodyLength = bodyData.length;
    if (bodyLength < 192) {
        // 1 octet
        [data appendBytes:&bodyLength length:1];
    } else if (bodyLength >= 192 && bodyLength <= 8383) {
        // 2 octet
        UInt8 buf[2] = {0,0};
        UInt16 twoOctets = CFSwapInt16HostToBig(bodyLength);
        buf[0] = (UInt8)((twoOctets - 192) >> 8) + 192;
        buf[1] = (UInt8)(twoOctets - 192);
        [data appendBytes:buf length:2];
    } else {
        // 5 octet
        UInt8 buf[5] = {0,0,0,0,0};

        UInt64 fiveOctets = CFSwapInt64HostToBig(bodyLength);
        UInt8 marker = 255;
        [data appendBytes:&marker length:1];

        buf[0] = 0xff;
		buf[1] = (UInt8)(fiveOctets >> 24);
		buf[2] = (UInt8)(fiveOctets >> 16);
		buf[3] = (UInt8)(fiveOctets >> 8);
		buf[4] = (UInt8)(fiveOctets);
        [data appendBytes:buf length:5];
    }

    return [data copy];
}

@end
