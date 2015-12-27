//
//  PGPPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "NSData+PGPUtils.h"

const UInt32 UnknownLength = UINT32_MAX;

@interface PGPPacket ()
@property (copy, readwrite) NSData *headerData;
@property (copy, readwrite) NSData *bodyData;
@end

@implementation PGPPacket

- (instancetype)init
{
    if (self = [super init]) {
        
    }
    return self;
}

- (instancetype)initWithHeader:(NSData *)headerData body:(NSData *)bodyData
{
    if (self = [self init]) {
        NSError *error = nil;
        _headerData = headerData;
        _bodyData = bodyData;
        [self parsePacketBody:self.bodyData error:&error];
        if (error) {
            return nil;
        }
    }
    return self;
}


- (NSUInteger)hash
{
#ifndef NSUINTROTATE
    #define NSUINT_BIT (CHAR_BIT * sizeof(NSUInteger))
    #define NSUINTROTATE(val, howmuch) ((((NSUInteger)val) << howmuch) | (((NSUInteger)val) >> (NSUINT_BIT - howmuch)))
#endif

    NSUInteger hash = [self.headerData hash];
    hash = NSUINTROTATE(hash, NSUINT_BIT / 2) ^ [self.bodyData hash];
    return hash;
}


- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSAssert(packetBody.length == self.bodyData.length, @"length mismach");
    return 0;
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
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
 *  @return Body data, headerLength, packetTag, nextPacketOffset and if body has indeterminateLength
 */
+ (NSData *) parsePacketHeader:(NSData*)data headerLength:(UInt32 *)headerLength nextPacketOffset:(NSUInteger *)nextPacketOffset packetTag:(PGPPacketTag *)tag indeterminateLength:(BOOL*)indeterminateLength
{
    UInt8 headerByte = 0;
    [data getBytes:&headerByte range:(NSRange){0,1}];
    
    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);
    BOOL isPartialBodyLength = NO;
    
    if (!isPGPHeader) {
        return nil;
    }
    UInt32 bodyLength;
    if (isNewFormat) {
        *headerLength = [self parseNewFormatHeaderPacket:data bodyLength:&bodyLength packetTag:tag partialBodyLength:&isPartialBodyLength];
    } else {
        *headerLength = [self parseOldFormatHeaderPacket:data bodyLength:&bodyLength packetTag:tag];
    }
    if (indeterminateLength) *indeterminateLength = NO;
    if (bodyLength == UnknownLength)
    {
        bodyLength = (UInt32)data.length - *headerLength;
        if (indeterminateLength) *indeterminateLength = YES;
    }
    if (nextPacketOffset != NULL) *nextPacketOffset = bodyLength + *headerLength;
    if (isPartialBodyLength)
    {
        UInt32 offset = *headerLength;
        NSMutableData *resultData = [NSMutableData dataWithData:[data subdataWithRange:(NSRange){offset, bodyLength}]];
        offset += bodyLength;
        do
        {
            // assume new header format
            PGPPacketTag nextTag;
            UInt32 packetBodyLength;
            UInt32 packetHeaderLength = [self parseNewFormatHeaderPacket:[data subdataWithRange:(NSRange){offset-1, data.length - (offset-1)}] bodyLength:&packetBodyLength packetTag:&nextTag partialBodyLength:&isPartialBodyLength] - 1;
            offset += packetHeaderLength;
            if (nextPacketOffset != NULL) *nextPacketOffset += packetHeaderLength + packetBodyLength;
            [resultData appendData:[data subdataWithRange:(NSRange){offset, MIN(packetBodyLength, data.length-offset)}]];
            offset += packetBodyLength;
        }
        while (isPartialBodyLength);
        return resultData;
    }
    return [data subdataWithRange:(NSRange){*headerLength, bodyLength}];
}

/**
 *  4.2.  Packet Headers
 *
 *  @param packetData Packet header
 *
 *  @return Header length
 */
+ (UInt32) parseNewFormatHeaderPacket:(NSData *)headerData bodyLength:(UInt32 *)length packetTag:(PGPPacketTag *)tag partialBodyLength:(BOOL *)isPartialBodyLength
{
    NSParameterAssert(headerData);

    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte length:1];
    // Bits 5-0 -- packet tag
    UInt8 packetTag = (headerByte << 2);
    packetTag = (packetTag >> 2);
    *tag = packetTag;

    // body length
    *isPartialBodyLength = NO;
    UInt32 bodyLength        = 0;
    UInt32 headerLength   = 2;

    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(1, MIN(5, headerData.length))].bytes;
    UInt8 firstOctet  = lengthOctets[0];

    if (lengthOctets[0] < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        bodyLength   = lengthOctets[0];
        headerLength = 1 + 1;
    } else if (lengthOctets[0] >= 192 && lengthOctets[0] < 224) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        bodyLength   = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
        headerLength = 1 + 2;
    } else if (lengthOctets[0] >= 224 && lengthOctets[0] < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        UInt32 partianBodyLength = 1 << (lengthOctets[0] & 0x1F);
        bodyLength               = partianBodyLength;
        headerLength             = 1 + 1;
        *isPartialBodyLength      = YES;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        bodyLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
        headerLength = 1 + 5;
    }
    *length = bodyLength;

    NSAssert(bodyLength > 0, @"The packet is of indeterminate length");

    return headerLength;
}

// 4.2.  Packet Headers
+ (UInt32) parseOldFormatHeaderPacket:(NSData *)headerData bodyLength:(UInt32 *)length packetTag:(PGPPacketTag *)tag
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

    UInt32 headerLength = 1;
    UInt32 bodyLength       = 0;
    switch (bodyLengthType) {
        case 0:
        {
            NSRange range = (NSRange) {1,1};
            [headerData getBytes:&bodyLength range:range];
            headerLength = (UInt32)(1 + range.length);
        }
            break;
        case 1:
        {
            UInt16 bLen = 0;
            NSRange range = (NSRange) {1,2};
            [headerData getBytes:&bLen range:range];
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            bodyLength = CFSwapInt16BigToHost(bLen);
            headerLength = (UInt32)(1 + range.length);
        }
            break;
        case 2:
        {
            NSRange range = (NSRange) {1,4};
            [headerData getBytes:&bodyLength range:range];
            bodyLength = CFSwapInt32BigToHost(bodyLength);
            headerLength = (UInt32)(1 + range.length);
        }
            break;
        case 3:
        {
#ifdef DEBUG
            NSLog(@"(Old) The packet is of indeterminate length - partially supported");
#endif
            bodyLength = UnknownLength;
            headerLength = 1;
        }
            break;

        default:
            break;
    }

    NSAssert(bodyLength > 0, @"Invalid packet length");
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
    [data appendData:[PGPPacket buildNewFormatLengthDataForData:bodyData]];

    return [data copy];
}

+ (NSData *)buildNewFormatLengthDataForData:(NSData *)bodyData
{
    NSMutableData *data = [NSMutableData data];
    // write length octets
    UInt64 bodyLength = bodyData.length;
    if (bodyLength < 192) {
        // 1 octet
        [data appendBytes:&bodyLength length:1];
    } else if (bodyLength >= 192 && bodyLength <= 8383) {
        // 2 octet
        UInt8 buf[2] = {0,0};
        UInt16 twoOctets = bodyLength;
        buf[0] = (UInt8)((twoOctets - 192) >> 8) + 192;
        buf[1] = (UInt8)(twoOctets - 192);
        [data appendBytes:buf length:2];
    } else {
        // 5 octet
        UInt64 fiveOctets = bodyLength;

        UInt8 buf[5] = {0xFF,0,0,0,0};
        buf[1] = (UInt8)(fiveOctets >> 24);
        buf[2] = (UInt8)(fiveOctets >> 16);
        buf[3] = (UInt8)(fiveOctets >> 8);
        buf[4] = (UInt8)(fiveOctets);
        [data appendBytes:buf length:5];
    }
    return [data copy];

}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone
{
    PGPPacket *copy = [[[self class] allocWithZone:zone] init];
    copy->_bodyData = self.bodyData;
    copy->_headerData = self.headerData;
    return copy;
}

#pragma mark - conversion

- (NSData *)packetData
{
    NSMutableData *result = [NSMutableData data];
    [result appendData:self.headerData];
    [result appendData:self.bodyData];
    return result;
}

@end
