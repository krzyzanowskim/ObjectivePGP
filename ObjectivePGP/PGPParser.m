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

@implementation PGPParser

- (BOOL) readKeys:(NSInputStream *)inputStream
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
        NSError *headerError = nil;
        PGPPacketHeader *header = [PGPPacketHeader readFromStream:inputStream error:&headerError];
        NSAssert(header, @"Header expected but not found");
        NSAssert(headerError, headerError.localizedDescription);
    }
    
    return NO;
}

@end
