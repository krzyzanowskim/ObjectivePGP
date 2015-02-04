//
//  PGPHeader.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeader.h"
#import "PGPCommon.h"
#import "NSInputStream+PGP.h"
#import "PGPFunctions.h"

typedef NS_ENUM(NSUInteger, PGPHeaderPacketTag) {
    PGPHeaderPacketTagNewFormat  = 0x40,
    PGPHeaderPacketTagAllwaysSet = 0x80
};

@interface PGPPacketHeader ()
@end

@implementation PGPPacketHeader

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    UInt8 headerByte;
    PGPPacketHeader *header = nil;
    if ([inputStream read:&headerByte maxLength:sizeof(headerByte)] > 0) {
        header = [[PGPPacketHeader alloc] init];
        if (![header parseHeaderByte:headerByte error:error]) {
            return nil;
        }
        
        if (header.isNew) {
            [header readNewLengthFromStream:inputStream error:error];
        } else {
            // Bits 1-0 -- length-type
            UInt8 oldLengthType = (UInt8)(headerByte << 6) >> 6;
            [header readOldLengthFromStream:inputStream lengthType:oldLengthType error:error];
        }
    }

    return header;
}

- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error
{
    if (!outputStream.hasSpaceAvailable) {
        return NO;
    }
    
    NSMutableData *data = [NSMutableData data];
    NSMutableData *lengthData = [NSMutableData data];
    
    UInt8 packetTag = PGPHeaderPacketTagAllwaysSet;
    if (self.isNew) {
        // New
        packetTag |= PGPHeaderPacketTagNewFormat;
        packetTag |= self.packetTag;
        if (self.isPartial) {
            int shift = (int)log2(self.bodyLength);
            UInt8 partialOctet = shift | 224;
            if (!isPowerOfTwo(self.bodyLength)) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Partial length have to be power of two"}];
                }
                return NO;
            }
            [lengthData appendBytes:&partialOctet length:1];
        } else if (self.bodyLength < 192) {
            [lengthData appendBytes:&_bodyLength length:1];
        } else if (self.bodyLength >= 192 && self.bodyLength <= 8393) {
            UInt8 buf[2] = {0,0};
            UInt16 twoOctets = self.bodyLength;
            buf[0] = (UInt8)((twoOctets - 192) >> 8) + 192;
            buf[1] = (UInt8)(twoOctets - 192);
            [lengthData appendBytes:buf length:2];
        } else {
            // 5 octet
            UInt8 buf[5] = {0,0,0,0,0};
            
            UInt64 fiveOctets = self.bodyLength;
            UInt8 marker = 255;
            [lengthData appendBytes:&marker length:1];
            
            buf[0] = 0xff;
            buf[1] = (UInt8)(fiveOctets >> 24);
            buf[2] = (UInt8)(fiveOctets >> 16);
            buf[3] = (UInt8)(fiveOctets >> 8);
            buf[4] = (UInt8)(fiveOctets);
            [lengthData appendBytes:buf length:5];
        }
    } else {
        // Old
        packetTag |= self.packetTag << 2;
        // determine length type 0-1 bit
        UInt8 lengthType = 0;
        if (self.isPartial || self.bodyLength == PGPIndeterminateLength) {
            // The packet is of indeterminate length.  The header is 1 octet
            // long, and the implementation must determine how long the packet
            // is.
            lengthType = 3;
        } else if (self.bodyLength <= UINT8_MAX) {
            lengthType = 0;
            [lengthData appendBytes:&_bodyLength length:1];
        } else if (self.bodyLength <= UINT16_MAX) {
            lengthType = 1;
            UInt16 bodyLengthBE = CFSwapInt16HostToBig(_bodyLength);
            [lengthData appendBytes:&bodyLengthBE length:2];
        } else if (self.bodyLength <= UINT32_MAX) {
            lengthType = 2;
            NSUInteger bodyLengthBE = CFSwapInt32HostToBig(_bodyLength);
            [lengthData appendBytes:&bodyLengthBE length:4];
        } else {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unsupported length type"}];
            }
            return NO;
        }
        packetTag |= lengthType;
    }
    [data appendBytes:&packetTag length:1];
    [data appendData:lengthData];

    if ([outputStream write:data.bytes maxLength:data.length] == -1) {
        return NO;
    }
    return YES;
}

#pragma mark - Length

- (BOOL) readNewLengthFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(inputStream.streamStatus == NSStreamStatusOpen);
    NSParameterAssert(error);
    self.isNew = YES;
    
    UInt8 firstOctet = [inputStream readUInt8];
    if (firstOctet < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        self.bodyLength = firstOctet;
    } else if (firstOctet >= 192 && firstOctet < 224) {
        // 4.2.2.2.  Two-Octet Lengths
        UInt8 secondOctet = [inputStream readUInt8];
        self.bodyLength   = ((firstOctet - 192) << 8) + (secondOctet) + 192;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        self.bodyLength = [inputStream readUInt32];
        //self.bodyLength   = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
    } else if (firstOctet >= 224 && firstOctet < 255) {
        // 4.2.2.4.  Partial Body Length
        // A Partial Body Length header is one octet long and encodes the length of only part of the data packet.
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        self.partial = YES;
        self.bodyLength = 1 << (firstOctet & 0x1F);
        
        if (self.bodyLength % 2 != 0) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Partial length is not a power of 2"}];
            }
            return NO;
        }
    }
    
    return YES;
}


- (BOOL) readOldLengthFromStream:(NSInputStream *)inputStream lengthType:(UInt8)lengthType error:(NSError * __autoreleasing *)error
{
    switch (lengthType) {
        case 0:
            self.bodyLength = [inputStream readUInt8];
            break;
        case 1:
        {
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            self.bodyLength = [inputStream readUInt16];
        }
            break;
        case 2:
        {
            self.bodyLength = [inputStream readUInt32];
        }
            break;
        case 3:
        {
#ifdef DEBUG
            NSLog(@"The packet is of indeterminate length.");
#endif
            // The packet is of indeterminate length.  The header is 1 octet
            // long, and the implementation must determine how long the packet
            // is.
            self.bodyLength = PGPIndeterminateLength;
            self.partial = YES;
        }
            break;
        default:
            NSAssert(false, @"Invalid packet header");
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid packet header"}];
            }
            return NO;
    }
    
    return YES;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone
{
    PGPPacketHeader *copy = [[PGPPacketHeader alloc] init];
    copy.isNew = _isNew;
    copy.packetTag = _packetTag;
    copy.bodyLength = _bodyLength;
    copy.partial = _partial;
    return copy;
}

#pragma mark - private

- (BOOL) parseHeaderByte:(Byte)headerByte error:(NSError * __autoreleasing *)error
{
    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    if (!isPGPHeader) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid sequence of packet header bytes"}];
        }
        return NO;
    }

    self.isNew = !!(headerByte & PGPHeaderPacketTagNewFormat);
    
    if (self.isNew) {
        // Bits 5-0 -- packet tag
        self.packetTag = ((UInt8)(headerByte << 2) >> 2);
    } else {
        //  Bits 5-2 -- packet tag
        self.packetTag = ((UInt8)(headerByte << 2) >> 4);
    }

    return YES;
}

@end
