//
//  PGPPacket.m
//  ObjectivePGP
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
#import "PGPSecretKeyPacket.h"
#import "PGPSecretSubKeyPacket.h"
#import "PGPLiteralPacket.h"
#import "PGPModificationDetectionCodePacket.h"
#import "PGPUserAttributePacket.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPCompressedPacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"

@implementation PGPPacketFactory

/**
 *  Parse packet data and return packet object instance
 *cc
 *  @param packetsData Data with all packets. Packet sequence data. Keyring.
 *  @param offset      offset of current packet
 *
 *  @return Packet instance object
 */
+ (PGPPacket * ) packetWithData:(NSData *)packetData offset:(NSUInteger)offset nextPacketOffset:(NSUInteger *)nextPacketOffset
{

    // parse header and get actual header data

    PGPPacketTag packetTag = 0;
    NSData *data = [packetData subdataWithRange:(NSRange) {offset, packetData.length - offset}];
    UInt32 headerLength;
    BOOL indeterminateLength;
    NSData *packetBodyData = [PGPPacket parsePacketHeader:data headerLength:&headerLength nextPacketOffset:nextPacketOffset packetTag:&packetTag indeterminateLength:&indeterminateLength];
    NSData *packetHeaderData = [packetData subdataWithRange:(NSRange) {offset, headerLength}];

    if (packetHeaderData.length > 0) {
        
        // Analyze body0
        PGPPacket * packet = nil;
        switch (packetTag) {
            case PGPPublicKeyPacketTag:
                packet = [[PGPPublicKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPPublicSubkeyPacketTag:
                packet = [[PGPPublicSubKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPSignaturePacketTag:
                packet = [[PGPSignaturePacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPUserAttributePacketTag:
                packet = [[PGPUserAttributePacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPUserIDPacketTag:
                packet = [[PGPUserIDPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPTrustPacketTag:
                packet = [[PGPTrustPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPLiteralDataPacketTag:
                packet = [[PGPLiteralPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPSecretKeyPacketTag:
                packet = [[PGPSecretKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPSecretSubkeyPacketTag:
                packet = [[PGPSecretSubKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPModificationDetectionCodePacketTag:
                packet = [[PGPModificationDetectionCodePacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPOnePassSignaturePacketTag:
                packet = [[PGPOnePassSignaturePacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPCompressedDataPacketTag:
                packet = [[PGPCompressedPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
//            case PGPSymmetricallyEncryptedDataPacketTag:
//                packet = [[PGPSymmetricallyEncryptedDataPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
//                break;
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag:
                packet = [[PGPSymmetricallyEncryptedIntegrityProtectedDataPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            case PGPPublicKeyEncryptedSessionKeyPacketTag:
                packet = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
            default:
                #ifdef DEBUG
                NSLog(@"Warning %s Packet tag %d is not supported", __PRETTY_FUNCTION__, packetTag);
                #endif
                
                packet = [[PGPPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
        }
        
        if (indeterminateLength) {
            packet.indeterminateLength = YES;
        }
        return packet;
    }
    return nil;
}

@end
