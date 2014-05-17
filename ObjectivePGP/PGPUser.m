//
//  PGPUser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUser.h"
#import "PGPUserIDPacket.h"

@interface PGPUser ()
@property (strong, nonatomic) PGPUserIDPacket *userIDPacket;
@end

@implementation PGPUser

- (instancetype) initWithPacket:(PGPUserIDPacket *)userPacket
{
    if (self = [self init]) {
        self.userIDPacket = userPacket;
        //TODO: self.userAttribute = userPacket.userAttribute;
    }
    return self;
}

- (NSString *)userID
{
    return self.userIDPacket.userID;
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
