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

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPacketFactory

/**
 *  Parse packet data and return packet object instance
 *cc
 *  @param packetData Data with all the packets. Packet sequence data. Keyring.
 *  @param offset     offset of current packet
 *
 *  @return Packet instance object
 */
+ (nullable PGPPacket *)packetWithData:(NSData *)packetData offset:(NSUInteger)offset nextPacketOffset:(nullable NSUInteger *)nextPacketOffset {
    // parse header and get actual header data
    PGPPacketTag packetTag = 0;
    UInt32 headerLength = 0;
    BOOL indeterminateLength = NO;
    let data = [packetData subdataWithRange:(NSRange){offset, packetData.length - offset}];
    let packetBodyData = [PGPPacket parsePacketHeader:data headerLength:&headerLength nextPacketOffset:nextPacketOffset packetTag:&packetTag indeterminateLength:&indeterminateLength];
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
//          case PGPSymmetricallyEncryptedDataPacketTag:
//              packet = [PGPSymmetricallyEncryptedDataPacket packetWithData:packetBodyData];
//              break;
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag:
                packet = [PGPSymmetricallyEncryptedIntegrityProtectedDataPacket packetWithBody:packetBodyData];
                break;
            case PGPPublicKeyEncryptedSessionKeyPacketTag:
                packet = [PGPPublicKeyEncryptedSessionKeyPacket packetWithBody:packetBodyData];
                break;
            default:
                PGPLogWarning(@"Packet tag %@ is not supported", @(packetTag));
                packet = [PGPPacket packetWithBody:packetBodyData];
                break;
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
