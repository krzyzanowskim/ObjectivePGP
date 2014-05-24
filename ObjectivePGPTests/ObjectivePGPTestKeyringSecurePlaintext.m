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
#import "PGPUser.h"
#import "PGPSignaturePacket.h"

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

//- (void)testLoadKeyring
//{
//    self.oPGP = [[ObjectivePGP alloc] init];
//    BOOL status = [self.oPGP loadKeyring:self.keyringPath];
//    XCTAssertTrue(status, @"Unable to load keyring");
//    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
//}
//
//- (void) testPrimaryKey
//{
//    [self.oPGP loadKeyring:self.keyringPath];
//
//    for (PGPKey *key in self.oPGP.keys) {
//        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
//        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
//        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
//        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
//    }
//}

- (void) testExport
{
    BOOL loadStatus = [self.oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(loadStatus, @"Keyring file should load properly");

    NSString *newDir = [@"ObjectivePGPTests_" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }

    NSMutableData *keysData = [NSMutableData data];
    for (PGPKey *key in self.oPGP.keys) {
        NSError *error = nil;
//        for (PGPUser *user in key.users) {
//            PGPSignaturePacket *signature = user.selfSignatures[0];
//            [signature sign:key user:user];
//        }
        NSData *keyData = [key export:&error];
        XCTAssertNotNil(keyData, @"Can't export key");
        [keysData appendData:keyData];
    }

    NSString *exportKeyringPath = [tmpDirectoryPath stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
    [keysData writeToFile:exportKeyringPath atomically:YES];
    NSLog(@"exported key to %@",exportKeyringPath);

    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
    loadStatus = [checkPGP loadKeyring:exportKeyringPath];
    XCTAssertTrue(loadStatus, @"Exported file should load properly");

    for (PGPKey *key in checkPGP.keys) {
        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
    }

    [[NSFileManager defaultManager] removeItemAtPath:exportKeyringPath error:nil];
}

@end
