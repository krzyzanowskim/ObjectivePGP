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

/**
 *  Parse packet data and return packet object instance
 *
 *  @param packetsData Data with all packets. Packet sequence data. Keyring.
 *  @param offset      offset of current packet
 *
 *  @return Packet instance object
 */
+ (id <PGPPacket> ) packetWithData:(NSData *)packetsData offset:(NSUInteger)offset
{
    NSData *guessPacketHeaderData = [packetsData subdataWithRange:(NSRange) {offset + 0, MIN(6,packetsData.length - offset)}]; // up to 6 octets for complete header

    // parse header and get actual header data
    UInt32 bodyLength       = 0;
    PGPPacketTag packetTag  = 0;
    NSData *packetHeaderData = [PGPPacket parsePacketHeader:guessPacketHeaderData bodyLength:&bodyLength packetTag:&packetTag];

    if (packetHeaderData.length > 0) {
        NSData *packetBodyData = [packetsData subdataWithRange:(NSRange) {offset + packetHeaderData.length, bodyLength}];
        // Analyze body
        NSLog(@"Reading packet tag %d", packetTag);
        id <PGPPacket> packet = nil;
        switch (packetTag) {
            case PGPPublicKeyPacketTag:
            {
                packet = [[PGPPublicKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
            }
                break;
            case PGPPublicSubkeyPacketTag:
            {
                packet = [[PGPPublicSubKeyPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
            }
                break;
            case PGPSignaturePacketTag:
            {
                packet = [[PGPSignaturePacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
            }
                break;
            case PGPUserIDPacketTag:
            {
                packet = [[PGPUserIDPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
            }
                break;
            case PGPTrustPacketTag:
            {
                packet = [[PGPTrustPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
            }
                break;
                
            default:
                NSLog(@"!!! Packet tag %d is not supported", packetTag);
                packet = [[PGPPacket alloc] initWithHeader:packetHeaderData body:packetBodyData];
                break;
        }
        return packet;
    }
    return nil;
}

@end
