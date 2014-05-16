//
//  ObjectivePGPTestKeyringSecureEncrypted.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ObjectivePGP.h"
#import "PGPSecretKeyPacket.h"

@interface ObjectivePGPTestKeyringSecureEncrypted : XCTestCase
@property (strong) NSString *keyringPath;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecureEncrypted

- (void)setUp
{
    [super setUp];
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.keyringPath = [bundle pathForResource:@"secring-test-encrypted" ofType:@"gpg"];
    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown
{
    [super tearDown];
    self.oPGP = nil;
}

- (void)testLoadKeyring
{
    BOOL status = [self.oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(status, @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
}

- (void) testUsers
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        XCTAssert(key.users.count == 1, @"Invalid users count");
    }
}

- (void) testPrimaryKey
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        PGPSecretKeyPacket *secretKey = key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertTrue(key.isEncrypted, @"Should be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"9528AAA17A9BC007", @"Invalid key identifier");
    }
}

- (void)testDecryption
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        NSError *decryptError = nil;
        BOOL status = [key decrypt:@"1234" error:&decryptError];
        XCTAssertTrue(status, @"Decryption failed");
        XCTAssertNil(decryptError, @"Decryption failed");
    }
}

@end
