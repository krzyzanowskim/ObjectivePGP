//
//  OpenPGPKeyring.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "OpenPGPKeyring.h"
#import "PGPPacketFactory.h"

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

    //TODO: whole keyring is parsed at once, for big files it may be a memory issue, change to stream later
    while (offset < keyringData.length) {
        id <PGPPacket> packet = [PGPPacketFactory packetWithData:keyringData offset:offset];
        offset = offset + packet.headerLength + packet.bodyLength;
    }
    return ret;
}

@end
