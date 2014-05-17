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
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.keyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown
{
    [super tearDown];
    self.oPGP = nil;
}

- (void)testLoadKeyring
{
    self.oPGP = [[ObjectivePGP alloc] init];
    BOOL status = [self.oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(status, @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
}

- (void) testPrimaryKey
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        PGPSecretKeyPacket *secretKey = key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
    }
}

- (void) testExport
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        NSError *error = nil;
        NSData *keyData = [key export:&error];
        NSLog(@"keyData: %@",keyData);
    }
}

@end
