//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "PGPPacketHeader.h"
#import "PGPPacketHeaderOld.h"
#import "PGPCommon.h"

@interface PGPPacketHeaderOldTests : XCTestCase

@end

@implementation PGPPacketHeaderOldTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testOldHeader0 {
    UInt8 headerBytes[] = {0x88, 0x10};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([packetHeader isKindOfClass:[PGPPacketHeaderOld class]]);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 2);
    XCTAssertEqual([packetHeader bodyLength], 0x10);
}

- (void)testOldHeader1 {
    UInt8 headerBytes[] = {0x89, 0x10, 0x10};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 3);
    XCTAssertEqual([packetHeader bodyLength], 0x1010);
}

- (void)testOldHeader2 {
    UInt8 headerBytes[] = {0x8A, 0x10, 0x10, 0x10, 0x10};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 5);
    XCTAssertEqual([packetHeader bodyLength], 0x10101010);
}

- (void)testOldHeader3 {
    UInt8 headerBytes[] = {0x8B, 0x10, 0x10, 0x10, 0x10};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(packetHeader);
    XCTAssertEqual([packetHeader packetTag], PGPSignaturePacketTag);
    XCTAssertEqual([packetHeader headerLength], 1);
    XCTAssertEqual([packetHeader bodyLength], PGPIndeterminateLength);
}

@end
