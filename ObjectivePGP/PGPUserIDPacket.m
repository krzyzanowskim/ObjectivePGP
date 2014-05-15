//
//  PGPUserID.m
//  ObjectivePGP
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

- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    _userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
    position = position + packetBody.length;

    return position;
}

@end
