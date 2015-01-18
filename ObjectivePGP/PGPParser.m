//
//  PGPParser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPParser.h"
#import "PGPPacketHeader.h"
#import "PGPPacketLengthHeader.h"
#import "PGPCommon.h"

@implementation PGPParser

- (BOOL) readStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
{
    switch (inputStream.streamStatus) {
        case NSStreamStatusAtEnd:
        case NSStreamStatusError:
        case NSStreamStatusWriting:
        case NSStreamStatusOpening:
            return NO;
            break;
        case NSStreamStatusClosed:
        case NSStreamStatusNotOpen:
            [inputStream open];
        default:
            break;
    }
    
    // read stream
    while (inputStream.hasBytesAvailable && inputStream.streamStatus != NSStreamStatusAtEnd) {
        // parse packet header
        PGPPacketHeader *header = [PGPPacketHeader readFromStream:inputStream error:error];
        NSAssert(error, @"Header expected, but not found!");
        if (!header) {
            return NO;
        }
        
        // read packet data
        if (header.bodyLengthIsPartial == NO) {
            // read packet body from stream
            // whole packet read at once which is not good for some big packets (literal etc)
            // however it's fine for small packets like key related
            UInt8 *bodyBuffer = calloc(1, header.bodyLength);
            [inputStream read:bodyBuffer maxLength:header.bodyLength];
            free(bodyBuffer);
        } else {
            //TODO: partial body length
            NSAssert(false, @"not supported");
        }
    }
    
    return NO;
}

@end
