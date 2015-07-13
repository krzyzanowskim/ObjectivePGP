//
//  PGPUserID.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"

@interface PGPPacket ()
@property (copy, readwrite) NSData *headerData;
@property (copy, readwrite) NSData *bodyData;
@end

@implementation PGPUserIDPacket

- (PGPPacketTag)tag
{
    return PGPUserIDPacketTag;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], self.userID];
}

- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    _userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
    position = position + packetBody.length;

    return position;
}

- (NSData *) exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];
    NSData *bodyData = [self.userID dataUsingEncoding:NSUTF8StringEncoding];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];
    return [data copy];
}


@end
