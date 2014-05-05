//
//  PGPUserID.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"

@implementation PGPUserIDPacket

- (instancetype) initWithBody:(NSData *)packetData
{
    if (self = [self init]) {
        [self parsePacketBody:packetData];
    }
    return self;
}


- (PGPPacketTag)tag
{
    return PGPUserIDPacketTag;
}

- (void) parsePacketBody:(NSData *)packetBody
{
    _userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
}

@end
