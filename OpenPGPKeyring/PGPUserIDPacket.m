//
//  PGPUserID.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"

@implementation PGPUserIDPacket

- (PGPPacketTag)tag
{
    return PGPUserIDPacketTag;
}

- (void) parsePacketBody:(NSData *)packetBody
{
    [super parsePacketBody:packetBody];

    _userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
}

@end
