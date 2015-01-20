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
#import "PGPKey.h"
#import "PGPSubKey.h"

@implementation PGPParser

- (BOOL) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error
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
    id lastParsedPacket = nil;
    PGPKey *key = nil;
    while (inputStream.hasBytesAvailable && inputStream.streamStatus != NSStreamStatusAtEnd) {
        lastParsedPacket = nil;
        // parse packet header
        PGPPacketHeader *header = [PGPPacketHeader readFromStream:inputStream error:error];
        NSAssert(error, @"Header expected, but not found!");
        if (!header) {
            NSAssert(*error != nil, @"Error expected");
            return NO;
        }
        
        // read packet data
        if (header.bodyLengthIsPartial == NO) {
            switch (header.packetTag) {
                case PGPPublicKeyPacketTag:
                case PGPPublicSubkeyPacketTag:
                {
                    // The Public-Key packet occurs first.
                    // Each of the following User ID packets provides the identity of the owner of this public key.
                    PGPPublicKeyPacket *packet = [PGPPublicKeyPacket readFromStream:inputStream error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        NSAssert(*error != nil, @"Error expected");
                        return NO;
                    }
                    
                    //TODO: flow is not finished!
                    // re-start key context
                    key = [[PGPKey alloc] init];
                    if (header.packetTag == PGPPublicKeyPacketTag) {
                        key.publicKeyPacket = packet;
                    } else if (header.packetTag == PGPPublicSubkeyPacketTag) {
                        // add subkey
                        PGPSubKey *subKey = [[PGPSubKey alloc] init];
                        subKey.publicKeyPacket = packet;
                        if (!key.subkeys) {
                            key.subkeys = [NSArray array];
                        }
                        key.subkeys = [key.subkeys arrayByAddingObject:subKey];
                    }
                    
                    lastParsedPacket = packet;
                }
                break;
                case PGPSignaturePacketTag:
                {
                    // key context
                    if (key) {
                        
                    }
                }
                break;
                case PGPUserIDPacketTag:
                {
                    PGPUserIDPacket *packet = [PGPUserIDPacket readFromStream:inputStream length:header.bodyLength error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        return NO;
                    }
                    
                    // key context
                    if (key) {
                        if (!key.userIDPackets) {
                            key.userIDPackets = [NSArray array];
                        }
                        key.userIDPackets = [key.userIDPackets arrayByAddingObject:packet];
                    }
                    
                    lastParsedPacket = packet;
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
        
        if (lastParsedPacket) {
            #ifdef DEBUG
            NSLog(@"%@ Parsed %@", self, lastParsedPacket);
            #endif
        } else {
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
