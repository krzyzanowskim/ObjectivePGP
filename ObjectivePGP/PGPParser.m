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
#import "PGPPublicKeyPacket.h"
#import "PGPUserIDPacket.h"
#import "PGPUser.h"
#import "PGPKey.h"
#import "PGPSubKey.h"
#import "PGPSignature.h"

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
    PGPKey *contextKey = nil;
    PGPUserIDPacket *contextUserIDPacket = nil;
    
    while (inputStream.hasBytesAvailable && inputStream.streamStatus != NSStreamStatusAtEnd) {
        id parsedPacket = nil;
        // parse packet header
        PGPPacketHeader *header = [PGPPacketHeader readFromStream:inputStream error:error];
        NSAssert(error, @"Header expected, but not found!");
        if (!header) {
            NSAssert(*error != nil, @"Error expected");
            return NO;
        }
        
        // read packet data
        if (header.isPartial == NO) {
            switch (header.packetTag) {
                case PGPPublicKeyPacketTag:
                case PGPPublicSubkeyPacketTag:
                {
                    // - One Public-Key packet
                    // The Public-Key packet occurs first.
                    // Each of the following User ID packets provides the identity of the owner of this public key.
                    PGPPublicKeyPacket *packet = [PGPPublicKeyPacket readFromStream:inputStream maxLength:header.bodyLength error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        NSAssert(*error != nil, @"Error expected");
                        return NO;
                    }
                    
                    //TODO: flow is not finished!
                    // re-start key context
                    contextKey = nil;
                    contextUserIDPacket = nil;
                    
                    if (header.packetTag == PGPPublicKeyPacketTag) {
                        PGPKey *key = [[PGPKey alloc] initWithPacket:packet];
                        contextKey = key;
                    } else if (header.packetTag == PGPPublicSubkeyPacketTag) {
                        // add subkey
                        PGPSubKey *subKey = [[PGPSubKey alloc] initWithPacket:packet];
                        if (!contextKey.subkeys) {
                            contextKey.subkeys = [NSArray array];
                        }
                        contextKey.subkeys = [contextKey.subkeys arrayByAddingObject:subKey];
                    }
                    
                    parsedPacket = packet;
                }
                break;
                case PGPSignaturePacketTag:
                {
                    // - After each User ID packet, zero or more Signature packets (certifications)
                    // Immediately following each User ID packet, there are zero or more Signature packets.
                    // Each Signature packet is calculated on the
                    // immediately preceding User ID packet and the initial Public-Key
                    // packet.
                    
                    // The signature serves to certify the corresponding public key
                    // and User ID.  In effect, the signer is testifying to his or her
                    // belief that this public key belongs to the user identified by this
                    // User ID.
                    
                    if (contextKey && contextUserIDPacket) {
                        PGPSignaturePacket *packet = [PGPSignaturePacket readFromStream:inputStream error:error];
                        NSAssert(packet, @"Missing or invalid packet %@", *error);
                        if (!packet) {
                            return NO;
                        }
                        PGPSignature *signature = [[PGPSignature alloc] initWithPacket:packet];
                        switch (signature.type) {
                            case PGPSignatureGenericCertificationUserIDandPublicKey:
                            case PGPSignatureCasualCertificationUserIDandPublicKey:
                            case PGPSignaturePositiveCertificationUserIDandPublicKey:
                            case PGPSignaturePersonalCertificationUserIDandPublicKey:
                                //if ([signature.issuerKeyID isEqualToKeyID:contextKey.packet.keyAlgorithm];
                                break;
                                
                            default:
                                break;
                        }
                        NSLog(@"Signature for UserID %@",contextUserIDPacket.userID);
                    }
                }
                break;
                case PGPUserIDPacketTag:
                {
                    // - One or more User ID packets. One at a time.
                    PGPUserIDPacket *packet = [PGPUserIDPacket readFromStream:inputStream maxLength:header.bodyLength error:error];
                    NSAssert(packet, @"Missing or invalid packet %@", *error);
                    if (!packet) {
                        return NO;
                    }
                    
                    PGPUser *user = [[PGPUser alloc] initWithPacket:packet];
                    // key context
                    if (contextKey) {
                        // Each of the following User ID packets provides the identity of the owner of this public key.
                        if (!contextKey.users) {
                            contextKey.users = [NSArray array];
                        }
                        contextKey.users = [contextKey.users arrayByAddingObject:user];
                    }
                    
                    contextUserIDPacket = packet;
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
        
        if (parsedPacket) {
            #ifdef DEBUG
            NSLog(@"%@ Parsed %@", self, parsedPacket);
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
