//
//  PGPHeaderLength.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketLengthHeader.h"
#import "PGPCommon.h"
#import "NSInputStream+PGP.h"

@implementation PGPPacketLengthHeader

- (BOOL) readNewFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(inputStream.streamStatus == NSStreamStatusOpen);
    NSParameterAssert(error);
        
    
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


- (BOOL) readOldFromStream:(NSInputStream *)inputStream lengthType:(UInt8)lengthType error:(NSError * __autoreleasing *)error
{
    switch (lengthType) {
        case 0:
            self.bodyLength = [inputStream readUInt8];
            break;
        case 1:
        {
            // value of a two-octet scalar is ((n[0] << 8) + n[1]).
            self.bodyLength = CFSwapInt16BigToHost([inputStream readUInt16]);
        }
            break;
        case 2:
        {
            self.bodyLength = CFSwapInt32BigToHost([inputStream readUInt32]);
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

@end
