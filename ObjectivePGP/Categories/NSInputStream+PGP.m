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
    return [self readUInt8:nil];
}

- (UInt8) readUInt8BytesAppendTo:(NSMutableData *)data
{
    NSParameterAssert(data);
    
    UInt8 result;
    UInt8 byte;
    result = [self readUInt8:&byte];
    [data appendBytes:&byte length:1];
    return result;
}

- (UInt8) readUInt8:(UInt8 *)readBytes
{
    UInt8 result = 0;
    [self read:&result maxLength:1];
    
    if (readBytes) {
        *readBytes = result;
    }
    return result;
}

- (UInt16) readUInt16
{
    return [self readUInt16:nil];
}

- (UInt16) readUInt16BytesAppendTo:(NSMutableData *)data
{
    NSParameterAssert(data);
    
    UInt16 result;
    UInt8 bytes[2];
    result = [self readUInt16:bytes];
    [data appendBytes:bytes length:sizeof(bytes)];
    return result;
}

- (UInt16) readUInt16:(UInt8 *)readBytes
{
    UInt8 bytes[2];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        if (readBytes) {
            bcopy(bytes, readBytes, sizeof(bytes));
        }
        return bytes[0] << 8 | bytes[1];
    }
    NSAssert(false,@"readUInt16 failed");
    return 0;
}

- (UInt32) readUInt32
{
    return [self readUInt32:nil];
}

- (UInt32) readUInt32BytesAppendTo:(NSMutableData *)data
{
    NSParameterAssert(data);
    
    UInt32 result;
    UInt8 bytes[4];
    result = [self readUInt32:bytes];
    [data appendBytes:bytes length:sizeof(bytes)];
    return result;
}


- (UInt32) readUInt32:(UInt8 *)readBytes
{
    UInt8 bytes[4];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        if (readBytes) {
            bcopy(bytes, readBytes, sizeof(bytes));
        }
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
    }
    NSAssert(false,@"readUInt32 failed");
    return 0;
}

@end
