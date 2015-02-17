//
//  NSData+PGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/02/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+PGP.h"

@implementation NSData (PGP)
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
@end
