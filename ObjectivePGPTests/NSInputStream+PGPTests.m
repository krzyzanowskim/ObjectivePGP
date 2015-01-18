//
//  NSInputStream+PGPTests.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "NSInputStream+PGPTests.h"
#import <XCTest/XCTest.h>

@implementation NSInputStream (PGPTests)

+ (NSInputStream *) inputStreamWithBytes:(UInt8[])bytes length:(int)length
{
    NSData *data = [NSData dataWithBytes:bytes length:length];
    NSInputStream *stream = [NSInputStream inputStreamWithData:data];
    NSAssert(stream, @"Can't to create stream with data %@", data);
    return stream;
}

@end
