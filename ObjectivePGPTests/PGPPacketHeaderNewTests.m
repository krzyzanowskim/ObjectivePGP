//
//  PGPPacketHeaderNewTests.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "PGPPacketHeader.h"
#import "PGPPacketHeaderNew.h"

@interface PGPPacketHeaderNewTests : XCTestCase

@end

@implementation PGPPacketHeaderNewTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testNewHeader0 {
    UInt8 headerBytes[] = {0xC2, 0x64};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([packetHeader isKindOfClass:[PGPPacketHeaderNew class]]);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 2);
    XCTAssertEqual([packetHeader bodyLength], 0x64);
}

- (void)testNewHeader1 {
    UInt8 headerBytes[] = {0xC2, 0xC5, 0xFB};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([packetHeader isKindOfClass:[PGPPacketHeaderNew class]]);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 3);
    XCTAssertEqual([packetHeader bodyLength], 1723);
}

- (void)testNewHeader2 {
    UInt8 headerBytes[] = {0xC2, 0xFF, 0x00, 0x01, 0x86, 0xA0};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([packetHeader isKindOfClass:[PGPPacketHeaderNew class]]);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 6);
    XCTAssertEqual([packetHeader bodyLength], 100000);
}

- (void)testNewHeader3 {
    UInt8 headerBytes[] = {0xC2, 0xEF};
    NSError *error;
    id <PGPPacketHeader> packetHeader = nil;
    XCTAssertNoThrowSpecificNamed(packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error], NSException, @"Partial body Length is not supported");
    XCTAssertNil(error);
//    XCTAssertTrue([packetHeader isKindOfClass:[PGPPacketHeaderNew class]]);
//    XCTAssertNotNil(packetHeader);
//    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
//    XCTAssertEqual([packetHeader isBodyLengthPartial], YES);
//    XCTAssertEqual([packetHeader headerLength], 2);
//    XCTAssertEqual([packetHeader bodyLength], 32768);
}

@end
