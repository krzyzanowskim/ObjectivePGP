//
//  ObjectivePGPTestSecurePlaintext.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ObjectivePGP.h"
#import "PGPSecretKeyPacket.h"

@interface ObjectivePGPTestKeyringSecurePlaintext : XCTestCase
@property (strong) NSString *keyringPath;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.keyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testLoadKeyring
{
    ObjectivePGP *oPGP = [[ObjectivePGP alloc] init];
    BOOL status = [oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(status, @"Unable to load keyring");
    XCTAssert(oPGP.keys.count == 1, @"Should load 1 key");

    PGPKey *key = oPGP.keys[0];
    PGPSecretKeyPacket *secretKey = key.primaryKeyPacket;

    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
    XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
}

@end
