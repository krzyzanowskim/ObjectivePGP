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

@interface ObjectivePGPTests : XCTestCase

@end

@implementation ObjectivePGPTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testOldHeader {
    UInt8 headerBytes[] = {};
    NSError *error;
    id <PGPPacketHeader> packetHeader = [PGPPacketHeader packetHeaderWithData:[NSData dataWithBytes:headerBytes length:sizeof(headerBytes)] error:&error];
    XCTAssertNotNil(packetHeader);
    XCTAssertNil(error);
}

@end
