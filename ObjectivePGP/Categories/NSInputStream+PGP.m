//
//  NSInputStream+PGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "NSInputStream+PGP.h"

@implementation NSInputStream (PGP)

- (UInt8) readUInt8
{
    UInt8 result = 0;
    [self read:&result maxLength:1];
    return result;
}

- (UInt16) readUInt16
{
    UInt8 bytes[2];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        return bytes[0] << 8 | bytes[1];
    }
    NSAssert(false,@"readUInt16 failed");
    return 0;
}

- (UInt32) readUInt32
{
    UInt8 bytes[4];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
    }
    NSAssert(false,@"readUInt32 failed");
    return 0;
}

@end
