//
//  OpenPGPKeyring.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "OpenPGPKeyring.h"
#import "PGPPacketFactory.h"
#import "PGPTransferableKey.h"
#import "PGPSignaturePacket.h"

@implementation OpenPGPKeyring

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
        offset = offset + packet.headerLength + packet.bodyLength;
    }

    // build keys from transferable sequence
    [packets enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        id <PGPPacket> packet = obj;
        NSLog(@"Packet %@",obj);

        PGPTransferableKey *currentTransferableKey = nil;

        // start new sequence
        if (packet.tag == PGPSecretKeyPacketTag || packet.tag == PGPPublicKeyPacketTag)
        {
            // One Public-Key packet
            currentTransferableKey = [[PGPTransferableKey alloc] init];
            currentTransferableKey.type = (packet.tag == PGPSecretKeyPacketTag) ? PGPTransferableSecret : PGPTransferablePublic;
        }

        if (currentTransferableKey && packet.tag == PGPSignaturePacketTag)
        {
            // Zero or more revocation signatures
            // PGPSignaturePacket *signaturePacket = packet;
            // currentTransferableKey.revocationSignatures = [currentTransferableKey.revocationSignatures arrayByAddingObject:packet];
        }

        // stop sequence

    }];

    return ret;
}

@end
