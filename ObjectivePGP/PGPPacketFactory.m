//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacketFactory.h"
#import "PGPPacket+Private.h"
#import "PGPCompressedPacket.h"
#import "PGPLiteralPacket.h"
#import "PGPModificationDetectionCodePacket.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPSymetricKeyEncryptedSessionKeyPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPPublicSubKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSecretSubKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPTrustPacket.h"
#import "PGPUserAttributePacket.h"
#import "PGPUserIDPacket.h"
#import "PGPMarkerPacket.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPacketFactory

/**
 *  Parse packet data and return packet object instance
 *
 *  @param packetData Data with all the packets. Packet sequence data. Keyring.
 *  @param offset     offset of current packet
 *
 *  @return Packet instance object
 */
+ (nullable PGPPacket *)packetWithData:(NSData *)packetData offset:(NSUInteger)offset consumedBytes:(nullable NSUInteger *)consumedBytes {
    // parse header and get actual header data
    PGPPacketTag packetTag = 0;
    UInt32 headerLength = 0;
    BOOL indeterminateLength = NO;
    let data = [packetData subdataWithRange:(NSRange){offset, packetData.length - offset}];
    let _Nullable packetBodyData = [PGPPacket readPacketBody:data headerLength:&headerLength consumedBytes:consumedBytes packetTag:&packetTag indeterminateLength:&indeterminateLength];
    if (!packetBodyData) {
      return nil;
    }
    let packetHeaderData = [packetData subdataWithRange:(NSRange){offset, headerLength}];

    if (packetHeaderData.length > 0) {
        // Analyze body0
        PGPPacket *packet = nil;
        switch (packetTag) {
            case PGPPublicKeyPacketTag:
                packet = [PGPPublicKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPPublicSubkeyPacketTag:
                packet = [PGPPublicSubKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPSignaturePacketTag:
                packet = [PGPSignaturePacket packetWithBody:packetBodyData];
                break;
            case PGPUserAttributePacketTag:
                packet = [PGPUserAttributePacket packetWithBody:packetBodyData];
                break;
            case PGPUserIDPacketTag:
                packet = [PGPUserIDPacket packetWithBody:packetBodyData];
                break;
            case PGPTrustPacketTag:
                packet = [PGPTrustPacket packetWithBody:packetBodyData];
                break;
            case PGPLiteralDataPacketTag:
                packet = [PGPLiteralPacket packetWithBody:packetBodyData];
                break;
            case PGPSecretKeyPacketTag:
                packet = [PGPSecretKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPSecretSubkeyPacketTag:
                packet = [PGPSecretSubKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPModificationDetectionCodePacketTag:
                packet = [PGPModificationDetectionCodePacket packetWithBody:packetBodyData];
                break;
            case PGPOnePassSignaturePacketTag:
                packet = [PGPOnePassSignaturePacket packetWithBody:packetBodyData];
                break;
            case PGPCompressedDataPacketTag:
                packet = [PGPCompressedPacket packetWithBody:packetBodyData];
                break;
            case PGPSymmetricallyEncryptedDataPacketTag:
                packet = [PGPSymmetricallyEncryptedDataPacket packetWithBody:packetBodyData];
                break;
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag:
                packet = [PGPSymmetricallyEncryptedIntegrityProtectedDataPacket packetWithBody:packetBodyData];
                break;
            case PGPPublicKeyEncryptedSessionKeyPacketTag:
                packet = [PGPPublicKeyEncryptedSessionKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPSymetricKeyEncryptedSessionKeyPacketTag:
                packet = [PGPSymetricKeyEncryptedSessionKeyPacket packetWithBody:packetBodyData];
                break;
            case PGPMarkerPacketTag:
                // Such a packet MUST be ignored when received.
                packet = [PGPMarkerPacket packetWithBody:packetBodyData];
                break;
            case PGPExperimentalPacketTag1:
            case PGPExperimentalPacketTag2:
            case PGPExperimentalPacketTag3:
            case PGPExperimentalPacketTag4:
                // Private or Experimental Values
                packet = [PGPPacket packetWithBody:packetBodyData];
                break;
            case PGPInvalidPacketTag:
                // Technical tag meaning the packet is invalid
                break;
            default:
                // The message is invalid, no packet
                break;
        }

        if (!packet) {
            PGPLogError(@"Invalid message.");
        }
        PGPAssertClass(packet, PGPPacket);

        if (indeterminateLength) {
            packet.indeterminateLength = YES;
        }
        return packet;
    }
    return nil;
}

@end

NS_ASSUME_NONNULL_END
