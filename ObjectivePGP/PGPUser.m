//
//  PGPUser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUser.h"
#import "PGPUserIDPacket.h"
#import "PGPUserAttributePacket.h"

@implementation PGPUser

- (instancetype) initWithUserIDPacket:(PGPUserIDPacket *)userPacket
{
    if (self = [self init]) {
        self.userIDPacket = userPacket;
    }
    return self;
}

- (NSString *)userID
{
    return self.userIDPacket.userID;
}

- (NSUInteger)hash
{
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + [_userID hash];
    result = prime * result + [_userAttribute hash];
    result = prime * result + [_selfSignatures hash];
    result = prime * result + [_otherSignatures hash];
    result = prime * result + [_revocationSignatures hash];
    result = prime * result + [_userIDPacket hash];

    return result;
}

- (NSArray *)otherSignatures
{
    if (!_otherSignatures) {
        _otherSignatures = [NSArray array];
    }
    return _otherSignatures;
}

- (NSArray *)directSignatures
{
    if (!_selfSignatures) {
        _selfSignatures = [NSArray array];
    }
    return _selfSignatures;
}

- (NSArray *)revocationSignatures
{
    if (!_revocationSignatures) {
        _revocationSignatures = [NSArray array];
    }
    return _revocationSignatures;
}

- (NSArray *)selfSignatures
{
    if (!_selfSignatures) {
        _selfSignatures = [NSArray array];
    }
    return _selfSignatures;
}

- (PGPUserIDPacket *)userIDPacket
{
    if (!_userIDPacket) {
        // build userIDPacket
    }
    return _userIDPacket;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], self.userID];
}

- (NSArray *) allPackets
{
    NSMutableArray *arr = [NSMutableArray array];

    [arr addObject:self.userIDPacket]; //TODO: || [arr addObject:self.userAttribute]

    for (id packet in self.revocationSignatures) {
        [arr addObject:packet];
    }

    for (id packet in self.selfSignatures) {
        [arr addObject:packet];
    }

    for (id packet in self.otherSignatures) {
        [arr addObject:packet];
    }

    return [arr copy];
}

@end
