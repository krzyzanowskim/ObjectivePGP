//
//  PGPHeader.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeader.h"
#import "PGPCommon.h"
#import "PGPPacketLengthHeader.h"

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
        
        PGPPacketLengthHeader *lengthHeader = [[PGPPacketLengthHeader alloc] init];
        if (header.isNew) {
            [lengthHeader readNewFromStream:inputStream error:error];
        } else {
            // Bits 1-0 -- length-type
            UInt8 oldLengthType = (UInt8)(headerByte << 6) >> 6;
            [lengthHeader readOldFromStream:inputStream lengthType:oldLengthType error:error];
        }
        header.bodyLength = lengthHeader.bodyLength;
        header.bodyLengthIsPartial = lengthHeader.isPartial;
    }

    return header;
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
