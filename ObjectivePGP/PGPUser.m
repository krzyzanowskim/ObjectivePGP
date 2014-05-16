//
//  PGPUser.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPUser.h"
#import "PGPUserIDPacket.h"

@implementation PGPUser

- (instancetype) initWithPacket:(PGPUserIDPacket *)userPacket
{
    if (self = [self init]) {
        self.userID = userPacket.userID;
        //self.userAttribute = userPacket.userAttribute;
    }
    return self;
}

- (NSArray *)otherSignatures
{
    if (_otherSignatures) {
        _otherSignatures = [NSArray array];
    }
    return _otherSignatures;
}

- (NSArray *)directSignatures
{
    if (_selfSignatures) {
        _selfSignatures = [NSArray array];
    }
    return _selfSignatures;
}

- (NSArray *)revocationSignatures
{
    if (_revocationSignatures) {
        _revocationSignatures = [NSArray array];
    }
    return _revocationSignatures;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], self.userID];
}

@end
