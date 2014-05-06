//
//  PGPPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketFactory.h"
#import "PGPPublicKeyPacket.h"
#import "PGPPublicSubKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPUserIDPacket.h"
#import "PGPTrustPacket.h"

@implementation PGPPacketFactory

+ (id <PGPPacket> ) packetWithData:(NSData *)packetData
{
    NSUInteger offset = 0;
    NSData *packetHeaderData = [packetData subdataWithRange:(NSRange) {offset + 0, MIN(6,packetData.length - offset)}]; // up to 6 octets for complete header

    PGPPacketFactory *packetFactory = [[PGPPacketFactory alloc] init];
    PGPPacket *packetGeneric = [[PGPPacket alloc] initWithHeaderData:packetHeaderData];
    if (packetGeneric) {
        NSData *packetBodyData = [packetData subdataWithRange:(NSRange) {offset + packetGeneric.headerLength,packetGeneric.bodyLength}];

        PGPPacket *packetInstance = [packetFactory getPacketInstance:packetBodyData forTag:packetGeneric.tag];

        packetInstance.tag          = packetGeneric.tag;
        packetInstance.headerLength = packetGeneric.headerLength;
        packetInstance.bodyLength   = packetGeneric.bodyLength;
        return packetInstance;
    }
    return nil;
}


/**
 *  Initialize packet instance with given body
 *
 *  @param packetBody Packet body
 *  @param tag Packet tag
 */
- (id <PGPPacket>) getPacketInstance:(NSData *)packetBody forTag:(PGPPacketTag)tag
{
    PGPPacket *packetInstance = nil;
    NSLog(@"Reading packet tag %d", tag);

    switch (tag) {
        case PGPPublicKeyPacketTag:
        {
            PGPPublicKeyPacket *publicKey = [[PGPPublicKeyPacket alloc] initWithBody:packetBody];
            packetInstance = publicKey;
#ifdef DEBUG
            NSLog(@"PGPPublicKeyPacket timestamp %@", [NSDate dateWithTimeIntervalSince1970:publicKey.timestamp]);
#endif
        }
            break;
        case PGPPublicSubkeyPacketTag:
        {
            PGPPublicSubKeyPacket *publicSubKey = [[PGPPublicSubKeyPacket alloc] initWithBody:packetBody];
            packetInstance = publicSubKey;
#ifdef DEBUG
            NSLog(@"PGPPublicSubKeyPacket timestamp %@", [NSDate dateWithTimeIntervalSince1970:publicSubKey.timestamp]);
#endif
        }
            break;
        case PGPSignaturePacketTag:
        {
            PGPSignaturePacket *signature = [[PGPSignaturePacket alloc] initWithBody:packetBody];
            packetInstance = signature;
#ifdef DEBUG
            NSLog(@"PGPSignaturePacket type %d", signature.signatureType);
#endif
        }
            break;
        case PGPUserIDPacketTag:
        {
            PGPUserIDPacket *userIDPacket = [[PGPUserIDPacket alloc] initWithBody:packetBody];
            packetInstance = userIDPacket;
#ifdef DEBUG
            NSLog(@"PGPUserIDPacket %@",userIDPacket.userID);
#endif
        }
            break;
        case PGPTrustPacketTag:
        {
            PGPTrustPacket *trustPacket = [[PGPTrustPacket alloc] initWithBody:packetBody];
            packetInstance = trustPacket;
#ifdef DEBUG
            NSLog(@"PGPTrustPacket %@",trustPacket.data);
#endif
        }
            break;

        default:
            NSLog(@"Packet tag %d is not yet supported", tag);
            break;
    }

    return packetInstance;
}

@end
