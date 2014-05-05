//
//  OpenPGPKeyring.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "OpenPGPKeyring.h"
#import "PGPPacket.h"

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
        NSUInteger bodyLength = 0;
        PGPPacketTag packetTag = 0;
        NSData *packetHeaderData = [keyringData subdataWithRange:(NSRange) {offset + 0,6}]; // up to 6 octets for complete header

        PGPPacket *packet = [[PGPPacket alloc] init];
        NSUInteger headerLength = [packet parsePacketHeader:packetHeaderData bodyLength:&bodyLength packetTag:&packetTag];

        NSData *packetBodyData = [keyringData subdataWithRange:(NSRange) {offset + headerLength,bodyLength}];
        [packet parsePacketTag:packetTag packetBody:packetBodyData];

        offset = offset + headerLength + bodyLength;
    }
    return ret;
}

@end
