//
//  PGPSubKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSubKey.h"

@interface PGPSubKey ()
@property (strong, readwrite) PGPPacket * keyPacket;
@end

@implementation PGPSubKey

- (instancetype) initWithPacket:(PGPPacket *)packet
{
    if (self = [self init]) {
        self.keyPacket = packet;
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@",[super description], [self.keyPacket description]];
}

- (NSArray *) allPackets
{
    NSMutableArray *arr = [NSMutableArray array];

    [arr addObject:self.keyPacket];

    if (self.revocationSignature) {
        [arr addObject:self.revocationSignature];
    }

    if (self.bindingSignature) {
        [arr addObject:self.bindingSignature];
    }

    return [arr copy];
}
@end
