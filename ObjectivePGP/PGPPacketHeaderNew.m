//
//  PGPPacketHeaderNew.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeaderNew.h"
#import "PGPPacket.h"
#import "PGPCommon.h"

@interface PGPPacketHeader ()
@property (assign, readwrite) NSInteger packetTag;
@property (assign, readwrite) UInt8 headerLength;
@property (assign, readwrite) UInt32 bodyLength;

@property (assign, readwrite, getter=isBodyLengthPartial) BOOL bodyLengthPartial;
@end

@implementation PGPPacketHeaderNew

- (instancetype)initWithData:(NSData *)headerData
{
    NSParameterAssert(headerData);
    
    if (!headerData) {
        return nil;
    }
    
    if (self = [self init]) {
        NSError *parseError = nil;
        if (![self parse:headerData error:&parseError]) {
            NSAssert(parseError, @"Header parse error");
            return nil;
        }
        
    }
    return self;
}

#pragma mark - Private

- (BOOL) parse:(NSData *)headerData error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(headerData.length > 0);
    
    UInt8 headerByte = 0;
    [headerData getBytes:&headerByte length:1];
    // Bits 5-0 -- packet tag
    self.packetTag = ((headerByte << 2) >> 2);
    
    // body length
    self.headerLength = 1;
    
    UInt8 *lengthOctets = (UInt8 *)[headerData subdataWithRange:NSMakeRange(1, MIN(5, headerData.length))].bytes;
    UInt8 firstOctet  = lengthOctets[0];
    
    if (lengthOctets[0] < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        self.bodyLength   = lengthOctets[0];
        self.headerLength = 1 + 1;
    } else if (lengthOctets[0] >= 192 && lengthOctets[0] <= 223) {
        // 4.2.2.2.  Two-Octet Lengths
        self.bodyLength   = ((lengthOctets[0] - 192) << 8) + (lengthOctets[1]) + 192;
        self.headerLength = 1 + 2;
    } else if (lengthOctets[0] >= 223 && lengthOctets[0] < 255) {
        // 4.2.2.4.  Partial Body Length
        // A Partial Body Length header is one octet long and encodes the length of only part of the data packet.
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        self.bodyLength   = 1 << (lengthOctets[0] & 0x1F);
        self.headerLength = 1 + 1;
        self.bodyLengthPartial   = YES;
        
        NSAssert(self.bodyLengthPartial == NO, @"Partial Body Lengths is not supported");
        // An implementation MAY use Partial Body Lengths for data packets, be
        // they literal, compressed, or encrypted. The first partial length
        // MUST be at least 512 octets long.  Partial Body Lengths MUST NOT be
        // used for any other packet types
        //
        //TODO: Note also that the last Body Length header can be a zero-length header.
        if (self.bodyLengthPartial && error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Partial Body Lengths is not supported"}];
            return NO;
        }
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        self.bodyLength   = (lengthOctets[1] << 24) | (lengthOctets[2] << 16) | (lengthOctets[3] << 8)  | lengthOctets[4];
        self.headerLength = 1 + 5;
    } else {
        NSAssert(false, @"Invalid packet header");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid packet header"}];
        }
        return NO;
    }

    return YES;
}

@end
