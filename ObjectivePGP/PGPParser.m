//
//  PGPParser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPParser.h"
#import "PGPCommon.h"
#import "NSInputStream+PGP.h"
#import "PGPPacketHeader.h"
#import "PGPPacketLengthHeader.h"
#import "PGPPublicKeyPacket.h"
#import "PGPUserIDPacket.h"

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
    id parsedPacket = nil;
    while (inputStream.hasBytesAvailable && inputStream.streamStatus != NSStreamStatusAtEnd) {
        parsedPacket = nil;
        // parse packet header
        PGPPacketHeader *header = [PGPPacketHeader readFromStream:inputStream error:error];
        NSAssert(error, @"Header expected, but not found!");
        if (!header) {
            NSAssert(*error != nil, @"Error expected");
            return NO;
        }
        
        // read packet data
        if (header.bodyLengthIsPartial == NO) {
            // read packet body from stream
            // whole packet read at once which is not good for some big packets (literal etc)
            // however it's fine for small packets like key related
            switch (header.packetTag) {
                case PGPPublicKeyPacketTag:
                case PGPPublicSubkeyPacketTag:
                {
                    PGPPublicKeyPacket *packet = [PGPPublicKeyPacket readFromStream:inputStream error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        return NO;
                    }
                    parsedPacket = packet;
                }
                break;
                case PGPUserIDPacketTag:
                {
                    PGPUserIDPacket *packet = [PGPUserIDPacket readFromStream:inputStream length:header.bodyLength error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        return NO;
                    }
                    parsedPacket = packet;
                }
                break;
                default:
                break;
            }
            
        } else {
            //TODO: partial body length
            NSAssert(false, @"not supported");
            return NO;
        }
        
        if (!parsedPacket) {
            // read unknown packets here
            UInt8 *bodyBuffer = calloc(1, header.bodyLength);
            [inputStream read:bodyBuffer maxLength:header.bodyLength];
            memset(bodyBuffer, arc4random(), header.bodyLength);
            free(bodyBuffer);
        }

    }
    
    return YES;
}

@end
