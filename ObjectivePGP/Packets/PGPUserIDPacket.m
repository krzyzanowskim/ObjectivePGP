//
//  PGPUserID.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUserIDPacket.h"
#import "PGPPacket+Private.h"
#import "PGPMacros.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPUserIDPacket ()

@property (nonatomic, copy, readwrite) NSString *userID;

@end

@implementation PGPUserIDPacket

- (instancetype)initWithUserID:(NSString *)userID {
    if ((self = [super init])) {
        _userID = [userID copy];
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPUserIDPacketTag;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], self.userID];
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    self.userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
    position = position + packetBody.length;

    return position;
}

- (nullable NSData *)export:(NSError *__autoreleasing *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return [self.userID dataUsingEncoding:NSUTF8StringEncoding];
    }];
}

@end

NS_ASSUME_NONNULL_END
