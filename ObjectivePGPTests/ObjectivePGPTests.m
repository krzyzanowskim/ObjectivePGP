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

@property (nonatomic, nullable) ObjectivePGP *pgp;
@property (nonatomic, readonly) NSBundle *bundle;

@end

@implementation ObjectivePGPTests

- (void)setUp {
    [super setUp];

    _bundle = [NSBundle bundleForClass:self.class];
    _pgp = [[ObjectivePGP alloc] init];
}

- (NSArray<PGPKey *> *)loadKeysFromFile:(NSString *)fileName {
    let path = [self.bundle pathForResource:fileName.stringByDeletingPathExtension ofType:fileName.pathExtension];
    return [self.pgp keysFromFile:path];
}

- (void)tearDown {
    [super tearDown];
    self.pgp = nil;
}

- (void)testGenerateNewKey {
    let keyGenerator = [[PGPKeyGenerator alloc] init];
    let key = [keyGenerator generateFor:@"Marcin <marcin@example.com>" passphrase:nil];
    XCTAssertNotNil(key);

    // test sign
    let dataToSign = [@"objectivepgp" dataUsingEncoding:NSUTF8StringEncoding];

    let sign = [self.pgp signData:dataToSign usingKey:key passphrase:nil detached:YES error:nil];
    XCTAssertNotNil(sign);

    BOOL isVerified = [self.pgp verifyData:dataToSign withSignature:sign usingKey:key error:nil];
    XCTAssertTrue(isVerified);

    // test export
    let exportedPublicKeyData = [key export:PGPPartialKeyPublic error:nil];
    XCTAssertNotNil(exportedPublicKeyData);
    let exportedSecretKeyData = [key export:PGPPartialKeySecret error:nil];
    XCTAssertNotNil(exportedSecretKeyData);

    let importedKeys = [self.pgp keysFromData:exportedPublicKeyData];
    XCTAssert(importedKeys.count == 1);
    XCTAssertEqualObjects(importedKeys.firstObject.keyID, key.keyID);
}

- (void)testGenerateNewKeyWithPassphrase {
    let keyGenerator = [[PGPKeyGenerator alloc] init];
    let key = [keyGenerator generateFor:@"Marcin <marcin@example.com>" passphrase:@"1234567890"];
    XCTAssertNotNil(key);

    let exportedPublicKeyData = [key export:PGPPartialKeyPublic error:nil];
    XCTAssertNotNil(exportedPublicKeyData);
    let exportedSecretKeyData = [key export:PGPPartialKeySecret error:nil];
    XCTAssertNotNil(exportedSecretKeyData);

    let importedPublicKeys = [self.pgp keysFromData:exportedPublicKeyData];
    XCTAssert(importedPublicKeys.count == 1);

    let importedSecretKeys = [self.pgp keysFromData:exportedPublicKeyData];
    XCTAssert(importedSecretKeys.count == 1);
}

- (void)testNotDuplicates {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys1];
    NSUInteger count1 = self.pgp.keys.count;

    let keys2 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys2];
    NSUInteger count2 = self.pgp.keys.count;

    XCTAssertEqual(count1, count2);
}

- (void)testKeyEquality {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    let keys2 = [self loadKeysFromFile:@"pubring-test-encrypted.gpg"];
    let keys3 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    let keys4 = [self loadKeysFromFile:@"secring-test-encrypted.gpg"];
    [self.pgp importKeys:keys1];
    [self.pgp importKeys:keys2];
    [self.pgp importKeys:keys3];
    [self.pgp importKeys:keys4];
    let encryptedKey = [self.pgp findKeyForIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(encryptedKey);
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    NSError *error;

    let decryptedKey = [encryptedKey decryptedWithPassphrase:@"1234" error:&error];
    XCTAssertFalse(decryptedKey.isEncryptedWithPassword);
    XCTAssertNotNil(decryptedKey);
    let decryptedKey2 = [encryptedKey decryptedWithPassphrase:@"12345" error:&error];
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    XCTAssertNil(decryptedKey2);

    XCTAssertTrue([self.pgp.keys containsObject:encryptedKey]);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/22
- (void)testIssue22 {
    let keys = [self loadKeysFromFile:@"issue22-original.asc"];
    [self.pgp importKeys:keys];
    let key = [self.pgp.keys firstObject];

    NSError *err = nil;
    PGPPartialKey * _Nullable decryptedKey = [key.secretKey decryptedWithPassphrase:@"weakpassphrase" error:&err];
    XCTAssertNotNil(decryptedKey);
    NSData *exportedKeyData = [decryptedKey export:nil];
    XCTAssert(exportedKeyData.length == 4869);
    XCTAssert(self.pgp.keys.count == 1, @"");
}

- (void)testIssue35 {
    let messagePath = [self.bundle pathForResource:@"issue35-message" ofType:@"asc"];
    let keys = [self loadKeysFromFile:@"issue35-key.asc"];

    NSError *error = nil;
    [self.pgp importKeys:keys];
    [self.pgp decryptData:[NSData dataWithContentsOfFile:messagePath] passphrase:nil error:&error];
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/53
- (void)testIssue53GNUDummyS2K {
    let keys1 = [self loadKeysFromFile:@"issue53-s2k-gnu-dummy.prv.asc"];
    let keys2 = [self loadKeysFromFile:@"issue53-s2k-gnu-dummy.pub.asc"];
    [self.pgp importKeys:keys1];
    [self.pgp importKeys:keys2];
    XCTAssertTrue(self.pgp.keys.count > 0);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/44
- (void)testIssue44 {
    let keys = [self loadKeysFromFile:@"issue44-keys.asc"];
    [self.pgp importKeys:keys];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let keyToSign = [self.pgp findKeyForIdentifier:@"71180E514EF122E5"];
    XCTAssertNotNil(keyToSign);

    let signatureData = [NSData dataWithContentsOfFile:[self.bundle pathForResource:@"issue44-keys" ofType:@"asc"]];
    let signature = [self.pgp signData:signatureData usingKey:keyToSign passphrase:@"passphrase" detached:YES error:nil];
    XCTAssertNotNil(signature);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/62
- (void)testIssue62 {
    let keys = [self loadKeysFromFile:@"issue62-keys.asc"];
    [self.pgp importKeys:keys];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let data = [NSData dataWithContentsOfFile:[self.bundle pathForResource:@"issue62-message" ofType:@"asc"]];
    NSError *error;
    let decryptedData = [self.pgp decryptData:data passphrase:nil error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(decryptedData);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/59
- (void)testIssue59 {
    let keys = [self loadKeysFromFile:@"issue59-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

@end
