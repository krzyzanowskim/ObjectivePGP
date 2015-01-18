//
//  PGPPacketHeaderNewTests.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "NSInputStream+PGPTests.h"
#import "PGPPacketHeader.h"

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
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];

    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 0x64);
}

- (void)testNewHeader1 {
    
    UInt8 headerBytes[] = {0xC2, 0xC5, 0xFB};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 1723);
}

- (void)testNewHeader2 {
    
    UInt8 headerBytes[] = {0xC2, 0xFF, 0x00, 0x01, 0x86, 0xA0};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 100000);
    XCTAssertEqual(header.bodyLengthIsPartial, NO);
}

- (void)testNewHeader3 {
    
    UInt8 headerBytes[] = {0xC2, 0xEF};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.isNew, YES);
    XCTAssertEqual(header.bodyLength, 32768);
    XCTAssertEqual(header.bodyLengthIsPartial, YES);
}

@end
