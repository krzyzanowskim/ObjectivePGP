//
//  NSMutableData+PGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/02/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "NSMutableData+PGP.h"

@implementation NSMutableData (PGP)

- (UInt16) readUInt16BE:(NSRange)range
{
    NSAssert(range.length == 2, @"Invalid length");
    UInt16 value = 0;
    [self getBytes:&value range:range];
    return CFSwapInt16BigToHost(value);
}

- (UInt32) readUInt32BE:(NSRange)range
{
    NSAssert(range.length == 4, @"Invalid length");
    UInt32 value = 0;
    [self getBytes:&value range:range];
    return CFSwapInt32BigToHost(value);
}

- (void) appendUInt8:(UInt8)value
{
    [self appendBytes:&value length:1];
}

- (void) appendUInt16BE:(UInt16)value
{
    UInt16 valueBE = CFSwapInt16HostToBig(value);
    [self appendBytes:&valueBE length:2];
}

- (void) appendUInt32BE:(UInt32)value
{
    UInt32 valueBE = CFSwapInt32HostToBig(value);
    [self appendBytes:&valueBE length:4];
}

@end
