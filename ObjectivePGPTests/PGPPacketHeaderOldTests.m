//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "NSInputStream+PGPTests.h"
#import "PGPPacketHeader.h"
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

- (NSData *) checkOutput:(PGPPacketHeader *)header expectedBytes:(const UInt8 *)expectedBytes length:(NSUInteger)length
{
    NSError *error;
    NSOutputStream *outputStream = [NSOutputStream outputStreamToMemory];
    [outputStream open];
    XCTAssertTrue([header writeToStream:outputStream error:&error]);
    XCTAssertNil(error);
    NSData *data = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    XCTAssertNotNil(data);
    XCTAssertEqualObjects([NSData dataWithBytes:expectedBytes length:length], data);
    [outputStream close];
    return data;
}

- (void)testOldHeader0 {
    UInt8 headerBytes[] = {0x88, 0x10};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 0x10);

    [self checkOutput:header expectedBytes:headerBytes length:sizeof(headerBytes)];
}

- (void)testOldHeader1 {
    UInt8 headerBytes[] = {0x89, 0x10, 0x10};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 0x1010);
    
    [self checkOutput:header expectedBytes:headerBytes length:sizeof(headerBytes)];
}

- (void)testOldHeader2 {
    UInt8 headerBytes[] = {0x8A, 0x10, 0x10, 0x10, 0x10};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, 0x10101010);

    [self checkOutput:header expectedBytes:headerBytes length:sizeof(headerBytes)];
}

- (void)testOldHeaderIndeterminateLength {
    UInt8 headerBytes[] = {0x8B, 0x10, 0x10, 0x10, 0x10};
    NSError *error;
    
    NSInputStream *stream = [NSInputStream inputStreamWithBytes:headerBytes length:sizeof(headerBytes)];
    [stream open];
    PGPPacketHeader *header = [PGPPacketHeader readFromStream:stream error:&error];
    [stream close];
    
    XCTAssertNil(error);
    XCTAssertNotNil(header);
    XCTAssertEqual(header.packetTag, PGPSignaturePacketTag);
    XCTAssertEqual(header.bodyLength, PGPIndeterminateLength);
    XCTAssertTrue(header.isPartial);
    
    [self checkOutput:header expectedBytes:headerBytes length:1];
}

@end
