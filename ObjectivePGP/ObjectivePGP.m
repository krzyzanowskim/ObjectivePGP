//
//  ObjectivePGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPPacketFactory.h"
#import "PGPTransferableKey.h"
#import "PGPSignaturePacket.h"
#import "PGPUserIDPacket.h"

@implementation ObjectivePGP

- (BOOL) open:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
        return NO;
    }

    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
    if (!ringData) {
        return NO;
    }

    [self parseKeyring:ringData];
    return YES;
}

#pragma mark - Parse keyring

- (BOOL) parseKeyring:(NSData *)keyringData
{
    BOOL ret = NO;

    NSUInteger offset = 0;

    NSMutableArray *packets = [NSMutableArray array];
    //TODO: whole keyring is parsed at once, for big files it may be a memory issue, change to stream later
    while (offset < keyringData.length) {
        id <PGPPacket> packet = [PGPPacketFactory packetWithData:keyringData offset:offset];
        if (packet) {
            [packets addObject:packet];
        }
        offset = offset + packet.headerData.length + packet.bodyData.length;
    }

    // single key sequence
    //TODO: multiple sequences
    PGPTransferableKey *transferableKey = [[PGPTransferableKey alloc] init];
    [transferableKey loadPackets:packets];

    // single sequence
//    NSUInteger i = 0;
//    id <PGPPacket> packet = nil;
//    PGPTransferableKey *transferableKey = [[PGPTransferableKey alloc] init];
//
//    // One Public-Key packet
//    packet = packets[i++];
//    transferableKey.type = (packet.tag == PGPSecretKeyPacketTag) ? PGPTransferableSecret : PGPTransferablePublic;
//
//    // Zero or more revocation signatures
//    if (packet.tag == PGPSignaturePacketTag) {
//        PGPSignaturePacket *signaturePacket = packet;
//        if (signaturePacket.type == PGPSignatureKeyRevocation) {
//            transferableKey.revocationSignatures = [transferableKey.revocationSignatures arrayByAddingObject:signaturePacket];
//        }
//    }
//
//    // One or more User ID packets
//    if (packet.tag == PGPUserIDPacketTag) {
//        PGPUserIDPacket *userIDPacket = packet;
//        
//    }

//    // build keys from transferable sequence
//    __block NSString *userIDContext = nil;
//    __block BOOL isSubkeyContext = NO;
//    __block PGPTransferableKey *currentTransferableKey = nil;
//
//    [packets enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
//        id <PGPPacket> packet = obj;
//        NSLog(@"Packet %@",obj);
//
//        // start new sequence
//        if (packet.tag == PGPSecretKeyPacketTag || packet.tag == PGPPublicKeyPacketTag)
//        {
//            // One Public-Key packet
//            currentTransferableKey = [[PGPTransferableKey alloc] init];
//            currentTransferableKey.type = (packet.tag == PGPSecretKeyPacketTag) ? PGPTransferableSecret : PGPTransferablePublic;
//            userIDContext = nil;
//            isSubkeyContext = NO;
//        }
//
//        // Zero or more revocation signatures
//        if (currentTransferableKey && packet.tag == PGPSignaturePacketTag)
//        {
//            PGPSignaturePacket *signaturePacket = packet;
//            switch (signaturePacket.type) {
//                case PGPSignatureKeyRevocation:
//                {
//                    if (!isSubkeyContext) {
//                        currentTransferableKey.revocationSignatures = [currentTransferableKey.revocationSignatures arrayByAddingObject:packet];
//                    }
//                }
//                    break;
//                case PGPSignatureGenericCertificationUserIDandPublicKey:
//                case PGPSignaturePersonalCertificationUserIDandPublicKey:
//                case PGPSignatureCasualCertificationUserIDandPublicKey:
//                case PGPSignaturePositiveCertificationUserIDandPublicKey:
//                {
//                    if (userIDContext && currentTransferableKey.users[userIDContext]) {
//                        NSArray *signatures = currentTransferableKey.userSignatures[userIDContext];
//                        signatures = [(signatures ?: [NSArray array]) arrayByAddingObject:signaturePacket];
//                    }
//                }
//                    break;
//                default:
//                    break;
//            }
//
//            if (isSubkeyContext) {
//                isSubkeyContext = NO;
//            }
//        }
//
//        if (currentTransferableKey && packet.tag == PGPUserAttributePacketTag) {
//            //TODO
//            userIDContext = nil;
//            isSubkeyContext = NO;
//        }
//
//        // One or more User ID packets
//        if (currentTransferableKey && packet.tag == PGPUserIDPacketTag)
//        {
//            PGPUserIDPacket *userIDPacket = packet;
//            currentTransferableKey.users[userIDPacket.userID] = packet;
//            userIDContext = userIDPacket.userID;
//            isSubkeyContext = NO;
//            // After each User ID packet, zero or more Signature packets (certifications)
//        }
//
//        //TODO: attribute packet is not supported
//
//        // Zero or more Subkey packets
//        if (currentTransferableKey && (packet.tag == PGPSecretSubkeyPacketTag || packet.tag == PGPPublicSubkeyPacketTag))
//        {
//            currentTransferableKey.subkeys = [currentTransferableKey.subkeys arrayByAddingObject:packet];
//            isSubkeyContext = YES;
//            userIDContext = nil;
//            // After each Subkey packet, one Signature packet, plus optionally a revocation
//        }
//
//        // stop sequence
//
//    }];

    return ret;
}

@end
