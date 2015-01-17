//
//  PGPParser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPParser.h"
#import "PGPPacketHeader.h"

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
            [inputStream open];
        default:
            break;
    }
    // read stream
    while (inputStream.hasBytesAvailable && inputStream.streamStatus != NSStreamStatusAtEnd) {
        // search for packets
        uint8_t bytes[6];
        [inputStream read:bytes maxLength:6]; //TODO: what if not
        
        
    }
    
    return NO;
}

@end
