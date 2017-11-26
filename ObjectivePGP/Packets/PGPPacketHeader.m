//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacketHeader.h"
#import "PGPMacros+Private.h"
#import "PGPTypes.h"
#import "PGPLogging.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPacketHeader

- (instancetype)init {
    if ((self = [super init])) {
        _packetTag = PGPInvalidPacketTag;
        _bodyLength = PGPUnknownLength;
        _partialLength = NO;
        _indeterminateLength = NO;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"headerLength: %@, bodyLength: %@, isPartial: %@", @(self.headerLength), @(self.bodyLength), self.isPartialLength ? @"YES" : @"NO"];
}

+ (void)getLengthFromNewFormatOctets:(NSData *)lengthOctetsData bodyLength:(UInt32 *)bodyLength bytesCount:(UInt8 *)bytesCount isPartial:(BOOL *)isPartial {
    const UInt8 *lengthOctets = lengthOctetsData.bytes;

    if (lengthOctets[0] < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        *bodyLength = lengthOctets[0];
        *bytesCount = 1;
    } else if (lengthOctets[0] >= 192 && lengthOctets[0] < 224) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        *bodyLength = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
        *bytesCount = 2;
    } else if (lengthOctets[0] >= 224 && lengthOctets[0] < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        *bodyLength = 1 << (lengthOctets[0] & 0x1F);
        *isPartial = YES;
        *bytesCount = 1;
    } else if (lengthOctets[0] == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        *bodyLength = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8) | lengthOctets[4];
        *bytesCount = 5;
    } else {
        // indeterminate length? that's not how it suppose to work, buy hey!
        PGPLogWarning(@"Unexpected indeterminate length for the packet.");
        *bodyLength = PGPUnknownLength;
        *bytesCount = 1;
    }
}

// 4.2.  Packet Headers
+ (nullable PGPPacketHeader *)newFormatHeaderFromData:(NSData *)data {
    NSParameterAssert(data);

    if (data.length < 1) {
        return nil;
    }

    UInt8 headerByte = 0;
    [data getBytes:&headerByte length:1];
    // Bits 5-0 -- packet tag
    UInt8 packetTag = (UInt8)(headerByte << 2);
    packetTag = (packetTag >> 2);

    // up to 5 bytes for length
    UInt8 lengthOctetsCount = 0;
    UInt32 bodyLength = 0;
    BOOL isPartial = NO;
    let lengthOctets = [data subdataWithRange:(NSRange){1, MIN((NSUInteger)5, data.length - 1)}];
    [PGPPacketHeader getLengthFromNewFormatOctets:lengthOctets bodyLength:&bodyLength bytesCount:&lengthOctetsCount isPartial:&isPartial];

    PGPPacketHeader *header = [PGPPacketHeader new];
    header.packetTag = packetTag;
    header.headerLength = 1 + lengthOctetsCount; // packet header + length octets
    header.bodyLength = bodyLength;
    header.partialLength = isPartial;
    header.indeterminateLength = header.bodyLength == PGPUnknownLength;
    return header;
}

// 4.2. Packet Headers
+ (nullable PGPPacketHeader *)oldFormatHeaderFromData:(NSData *)data {
    NSParameterAssert(data);

    if (data.length < 1) {
        return nil;
    }

    UInt8 headerByte = 0;
    [data getBytes:&headerByte length:1];
    //  Bits 5-2 -- packet tag
    UInt8 packetTag = (UInt8)(headerByte << 2);
    packetTag = (packetTag >> 4);

    //  Bits 1-0 -- length-type
    UInt8 bodyLengthType = (UInt8)(headerByte << 6);
    bodyLengthType = bodyLengthType >> 6;

    BOOL isIndeterminateLength = NO;
    UInt32 headerLength = 1;
    UInt32 bodyLength = 0;
    switch (bodyLengthType) {
        case 0: {
            NSRange range = (NSRange){1, 1};
            [data getBytes:&bodyLength range:range];
            headerLength = (UInt32)(1 + range.length);
        } break;
        case 1: {
            UInt16 bLen = 0;
            NSRange range = (NSRange){1, 2};
            [data getBytes:&bLen range:range];
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            bodyLength = CFSwapInt16BigToHost(bLen);
            headerLength = (UInt32)(1 + range.length);
        } break;
        case 2: {
            NSRange range = (NSRange){1, 4};
            [data getBytes:&bodyLength range:range];
            bodyLength = CFSwapInt32BigToHost(bodyLength);
            headerLength = (UInt32)(1 + range.length);
        } break;
        case 3: {
            PGPLogWarning(@"(Old format) The packet is of indeterminate length");
            bodyLength = PGPUnknownLength;
            headerLength = 1;
            isIndeterminateLength = YES;
        } break;
        default:
            PGPLogWarning(@"Invalid packet length. Skipping...");
            return nil;
    }

    PGPPacketHeader *header = [PGPPacketHeader new];
    header.headerLength = headerLength;
    header.bodyLength = bodyLength;
    header.packetTag = packetTag;
    header.partialLength = NO;
    header.indeterminateLength = isIndeterminateLength;

    return header;
}

@end

NS_ASSUME_NONNULL_END

