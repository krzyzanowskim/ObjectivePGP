//
//  PGPInputStreamCategoryTests.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "NSInputStream+PGP.h"
#import "NSInputStream+PGPTests.h"

@interface PGPInputStreamCategoryTests : XCTestCase

@end

@implementation PGPInputStreamCategoryTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void) testReadUInt8
{
    Byte bytes[] = {0x01};
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:bytes length:sizeof(bytes)];
    [stream open];
    XCTAssertNotNil(stream);
    UInt8 readByte;
    UInt8 result = [stream readUInt8:&readByte];
    XCTAssertEqual(result, 0x01);
    XCTAssertEqual(readByte, 0x01);
    [stream close];
}

- (void) testReadUInt16
{
    Byte bytes[] = {0x01, 0x02};
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:bytes length:sizeof(bytes)];
    [stream open];
    XCTAssertNotNil(stream);
    UInt8 readBytes[2];
    UInt16 result = [stream readUInt16BE:readBytes];
    XCTAssertEqual(result, 0x0102);
    for (int i = 0; i < sizeof(bytes); i++) {
        XCTAssertEqual(readBytes[i], bytes[i]);
    }
    [stream close];
}

- (void) testReadUInt32
{
    Byte bytes[] = {0x01, 0x02, 0x03, 0x04};
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:bytes length:sizeof(bytes)];
    [stream open];
    XCTAssertNotNil(stream);
    UInt8 readBytes[4];
    UInt32 result = [stream readUInt32BE:readBytes];
    XCTAssertEqual(result, 0x01020304);
    for (int i = 0; i < sizeof(bytes); i++) {
        XCTAssertEqual(readBytes[i], bytes[i]);
    }
    [stream close];
}
@end
