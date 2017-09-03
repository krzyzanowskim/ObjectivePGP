//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>
#import "PGPMacros+Private.h"
#import <XCTest/XCTest.h>

// sec   2048R/AEEF64C8 2014-05-03
// uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
// ssb   2048R/7D4FCA45 2014-05-03

// pub   2048R/AEEF64C8 2014-05-03
// Key fingerprint = 816E 6A80 8067 D41E 4CB0  3FCC 9469 0093 AEEF 64C8
// uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
// sub   2048R/7D4FCA45 2014-05-03

// pass ObjectivePGP

@interface ObjectivePGPTests : XCTestCase

@property (nonatomic) ObjectivePGP *oPGP;
@property (nonatomic) NSString *secringPathPlaintext, *secringPathEncrypted;
@property (nonatomic) NSString *pubringPlaintext, *pubringEncrypted;

@end

@implementation ObjectivePGPTests

- (void)setUp {
    [super setUp];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.secringPathPlaintext = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.secringPathEncrypted = [bundle pathForResource:@"secring-test-encrypted" ofType:@"gpg"];
    self.pubringPlaintext = [bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    self.pubringEncrypted = [bundle pathForResource:@"pubring-test-encrypted" ofType:@"gpg"];

    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown {
    [super tearDown];
    self.oPGP = nil;
}

- (void)testGenerateNewKey {
    let keyGenerator = [[PGPKeyGenerator alloc] init];
    let key = [keyGenerator generateFor:@"Marcin <marcin@example.com>"];
    XCTAssertNotNil(key);

    // test sign
    let data = [@"objectivepgp" dataUsingEncoding:NSUTF8StringEncoding];

    let sign = [self.oPGP signData:data usingKey:key passphrase:nil detached:YES error:nil];
    XCTAssertNotNil(sign);

    BOOL verified = [self.oPGP verifyData:data withSignature:sign usingKey:key error:nil];
    XCTAssertTrue(verified);
}

- (void)testNotDuplicates {
    [self.oPGP importKeysFromFile:self.pubringPlaintext];
    NSUInteger count1 = self.oPGP.keys.count;
    [self.oPGP importKeysFromFile:self.pubringPlaintext];
    NSUInteger count2 = self.oPGP.keys.count;

    XCTAssertEqual(count1, count2);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/22
- (void)testIssue22 {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *originalKeyFilePath = [bundle pathForResource:@"issue22-original" ofType:@"asc"];
    [self.oPGP importKeysFromFile:originalKeyFilePath];
    let key = [self.oPGP.keys anyObject];

    NSError *err = nil;
    XCTAssertTrue([key.secretKey decrypt:@"weakpassphrase" error:&err]);
    NSData *exportedKeyData = [key.secretKey export:nil];
    XCTAssert(exportedKeyData.length == 4869);
    XCTAssert(self.oPGP.keys.count == 1, @"");
}

- (void)testIssue35 {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *messagePath = [bundle pathForResource:@"issue35-message" ofType:@"asc"];
    NSString *keyPath = [bundle pathForResource:@"issue35-key" ofType:@"asc"];
    NSError *error = nil;
    [self.oPGP importKeysFromFile:keyPath];
    [self.oPGP decryptData:[NSData dataWithContentsOfFile:messagePath] passphrase:nil error:&error];
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/53
- (void)testIssue53GNUDummyS2K {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *keyPathPrv = [bundle pathForResource:@"issue53-s2k-gnu-dummy.prv" ofType:@"asc"];
    NSString *keyPathPub = [bundle pathForResource:@"issue53-s2k-gnu-dummy.pub" ofType:@"asc"];
    XCTAssertTrue([self.oPGP importKeysFromFile:keyPathPrv]);
    XCTAssertTrue([self.oPGP importKeysFromFile:keyPathPub]);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/44
- (void)testIssue44 {
    let pgp = self.oPGP;
    let bundle = [NSBundle bundleForClass:[self class]];
    let keysPath = [bundle pathForResource:@"issue44-keys" ofType:@"asc"];

    let keys = [pgp importKeysFromFile:keysPath];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let keyToSign = [pgp findKeyForIdentifier:@"71180E514EF122E5"];
    XCTAssertNotNil(keyToSign);

    let signatureData = [NSData dataWithContentsOfFile:keysPath];
    let signature = [pgp signData:signatureData usingKey:keyToSign passphrase:@"passphrase" detached:YES error:nil];
    XCTAssertNotNil(signature);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/62
- (void)testIssue62 {
    let pgp = self.oPGP;
    let bundle = [NSBundle bundleForClass:[self class]];
    let keysPath = [bundle pathForResource:@"issue62-keys" ofType:@"asc"];
    let keys = [pgp importKeysFromFile:keysPath];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    NSError *error;
    let data = [NSData dataWithContentsOfFile:[bundle pathForResource:@"issue62-message" ofType:@"asc"]];
    let decryptedData = [pgp decryptData:data passphrase:nil error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(decryptedData);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/67
- (void)testIssue67 {
    let pgp = self.oPGP;
    let bundle = [NSBundle bundleForClass:[self class]];
    let keysPath = [bundle pathForResource:@"issue67-key" ofType:@"asc"];
    let keys = [pgp importKeysFromFile:keysPath];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    NSError *error;
    let signatureData = [NSData dataWithContentsOfFile:keysPath];
    let signature = [pgp signData:signatureData usingKey:keys.anyObject passphrase:nil detached:YES error:&error];
    XCTAssertNotNil(signature);
    XCTAssertNil(error);
}

@end
