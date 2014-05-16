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
    PGPKey *key = [[PGPKey alloc] initWithPackets:packets];

    return ret;
}

@end
