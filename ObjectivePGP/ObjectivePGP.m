//
//  ObjectivePGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPPacketFactory.h"
#import "PGPKey.h"
#import "PGPSignaturePacket.h"
#import "PGPUserIDPacket.h"

@implementation ObjectivePGP

- (NSArray *)keys
{
    if (!_keys) {
        _keys = [NSArray array];
    }
    return _keys;
}

/**
 *  Load keyring file (secring or pubring)
 *
 *  @param path Path to file
 *
 *  @return YES on success
 */
- (BOOL) loadKeyring:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:NO]) {
        return NO;
    }

    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
    if (!ringData) {
        return NO;
    }

    NSArray *parsedKeys = [self parseKeyring:ringData];
    if (parsedKeys.count == 0) {
        return NO;
    }

    self.keys = [self.keys arrayByAddingObjectsFromArray:parsedKeys];

    return YES;
}

- (NSData *) signData:(NSData *)dataToSign withSecretKey:(PGPKey *)secretKey
{
    NSData *signaturePacketData = nil;

    // Some defaults
    PGPHashAlgorithm preferedHashAlgorithm = PGPHashSHA1;

    PGPSignaturePacket *signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument
                                                                hashAlgorithm:preferedHashAlgorithm];

    signaturePacketData = [signaturePacket createSignatureForData:dataToSign secretKey:secretKey];
    return signaturePacketData;
}

#pragma mark - Parse keyring

/**
 *  Parse keyring data
 *
 *  @param keyringData Keyring data
 *
 *  @return Array of PGPKey
 */
- (NSArray *) parseKeyring:(NSData *)keyringData
{
    NSMutableArray *keys = [NSMutableArray array];
    NSMutableArray *accumulatedPackets = [NSMutableArray array];
    NSUInteger offset = 0;

    while (offset < keyringData.length) {
        
        PGPPacket *packet = [PGPPacketFactory packetWithData:keyringData offset:offset];
        if (packet) {
            if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
                PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
                [keys addObject:key];
                [accumulatedPackets removeAllObjects];
            }
            [accumulatedPackets addObject:packet];
        }

        offset = offset + packet.headerData.length + packet.bodyData.length;
    }

    if (accumulatedPackets.count > 1) {
        PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
        [keys addObject:key];
        [accumulatedPackets removeAllObjects];
    }


    return [keys copy];
}

@end
