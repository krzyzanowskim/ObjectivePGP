//
//  NSOutputStream+PGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/02/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "NSOutputStream+PGP.h"

@implementation NSOutputStream (PGP)

- (BOOL) writeUInt8:(UInt8)value
{
    UInt8 bytes[1];
    bcopy(&value, bytes, sizeof(bytes));
    if ([self write:bytes maxLength:sizeof(bytes)] == -1) {
        return NO;
    }
    return YES;

}

- (BOOL) writeUInt16:(UInt16)value
{
    UInt8 bytes[2];
    bcopy(&value, bytes, sizeof(bytes));
    if ([self write:bytes maxLength:sizeof(bytes)] == -1) {
        return NO;
    }
    return YES;
}


- (BOOL) writeUInt32:(UInt32)value
{
    UInt8 bytes[4];
    bcopy(&value, bytes, sizeof(bytes));
    if ([self write:bytes maxLength:sizeof(bytes)] == -1) {
        return NO;
    }
    return YES;
}

- (BOOL) writeData:(NSData *)data
{
    if ([self write:data.bytes maxLength:data.length] == -1) {
        return NO;
    }
    return YES;
}

@end
