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

- (UInt16) readUInt16BE
{
    return [self readUInt16BE:nil];
}

- (UInt16) readUInt16BEBytesAppendTo:(NSMutableData *)data
{
    NSParameterAssert(data);
    
    UInt16 result;
    UInt8 bytes[2];
    result = [self readUInt16BE:bytes];
    [data appendBytes:bytes length:sizeof(bytes)];
    return result;
}

- (UInt16) readUInt16BE:(UInt8 *)readBytes
{
    UInt8 bytes[2];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        if (readBytes) {
            bcopy(bytes, readBytes, sizeof(bytes));
        }
        UInt16 value = 0;
        bcopy(bytes, &value, sizeof(bytes));
        return CFSwapInt16BigToHost(value);
    }
    NSAssert(false,@"readUInt16 failed");
    return 0;
}

- (UInt32) readUInt32BE
{
    return [self readUInt32BE:nil];
}

- (UInt32) readUInt32BytesAppendTo:(NSMutableData *)data
{
    NSParameterAssert(data);
    
    UInt32 result;
    UInt8 bytes[4];
    result = [self readUInt32BE:bytes];
    [data appendBytes:bytes length:sizeof(bytes)];
    return result;
}


- (UInt32) readUInt32BE:(UInt8 *)readBytes
{
    UInt8 bytes[4];
    if ([self read:bytes maxLength:sizeof(bytes)] > 0) {
        if (readBytes) {
            bcopy(bytes, readBytes, sizeof(bytes));
        }
        UInt32 value;
        bcopy(bytes, &value, sizeof(bytes));
        return CFSwapInt32BigToHost(value);
    }
    NSAssert(false,@"readUInt32 failed");
    return 0;
}

- (NSData *) readDataLength:(NSUInteger)length
{
    NSData *output = nil;
    UInt8 buffer[length];
    NSInteger readResult = [self read:buffer maxLength:length];
    if (readResult > 0) {
        output = [NSData dataWithBytes:buffer length:readResult]; // 8 bytes long
    }
    free(buffer);
    return output;
}

@end
