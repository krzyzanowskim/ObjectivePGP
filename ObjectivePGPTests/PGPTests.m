//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>
#import "PGPMacros+Private.h"
#import "PGPTestUtils.h"
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

    _bundle = PGPTestUtils.filesBundle;
    _pgp = [[ObjectivePGP alloc] init];
}

- (NSArray<PGPKey *> *)importKeysFromFile:(NSString *)fileName {
    let keys = [PGPTestUtils keysFromFile:fileName];
    [self.pgp importKeys:keys];
    return keys;
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

    let sign = [self.pgp sign:dataToSign usingKey:key passphrase:nil detached:YES error:nil];
    XCTAssertNotNil(sign);

    BOOL isVerified = [self.pgp verify:dataToSign withSignature:sign usingKey:key error:nil];
    XCTAssertTrue(isVerified);

    // test export
    let exportedPublicKeyData = [key export:PGPPartialKeyPublic error:nil];
    XCTAssertNotNil(exportedPublicKeyData);
    let exportedSecretKeyData = [key export:PGPPartialKeySecret error:nil];
    XCTAssertNotNil(exportedSecretKeyData);

    let importedKeys = [ObjectivePGP keysFromData:exportedPublicKeyData];
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

    let importedPublicKeys = [ObjectivePGP keysFromData:exportedPublicKeyData];
    XCTAssert(importedPublicKeys.count == 1);

    let importedSecretKeys = [ObjectivePGP keysFromData:exportedPublicKeyData];
    XCTAssert(importedSecretKeys.count == 1);
}

- (void)testNotDuplicates {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    NSUInteger count1 = self.pgp.keys.count;

    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    NSUInteger count2 = self.pgp.keys.count;

    XCTAssertEqual(count1, count2);
}

- (void)testKeyEquality {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self importKeysFromFile:@"pubring-test-encrypted.gpg"];
    [self importKeysFromFile:@"secring-test-plaintext.gpg"];
    [self importKeysFromFile:@"secring-test-encrypted.gpg"];
    let encryptedKey = [self.pgp findKeyWithIdentifier:@"9528AAA17A9BC007"];
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


- (void)testExportImport {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self importKeysFromFile:@"pubring-test-encrypted.gpg"];
    [self importKeysFromFile:@"secring-test-plaintext.gpg"];
    [self importKeysFromFile:@"secring-test-encrypted.gpg"];

    XCTAssertNotNil(self.pgp.keys.firstObject);
    NSUInteger keysCount = self.pgp.keys.count;

    for (PGPKey *key in self.pgp.keys) {
        let exportedKeyData = [key export:nil];
        let readKeys = [ObjectivePGP keysFromData:exportedKeyData];
        XCTAssertTrue(readKeys.count == 1);
        [self.pgp importKeys:readKeys];
    }

    XCTAssertEqual(self.pgp.keys.count, keysCount);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/22
- (void)testIssue22 {
    [self importKeysFromFile:@"issue22-original.asc"];
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
    [self importKeysFromFile:@"issue35-key.asc"];

    NSError *error = nil;
    [self.pgp decrypt:[NSData dataWithContentsOfFile:messagePath] passphrase:nil error:&error];
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/53
- (void)testIssue53GNUDummyS2K {
    [self importKeysFromFile:@"issue53-s2k-gnu-dummy.prv.asc"];
    [self importKeysFromFile:@"issue53-s2k-gnu-dummy.pub.asc"];
    XCTAssertTrue(self.pgp.keys.count > 0);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/44
- (void)testIssue44 {
    let keys = [self importKeysFromFile:@"issue44-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let keyToSign = [self.pgp findKeyWithIdentifier:@"71180E514EF122E5"];
    XCTAssertNotNil(keyToSign);

    let signatureData = [NSData dataWithContentsOfFile:[self.bundle pathForResource:@"issue44-keys" ofType:@"asc"]];
    let signature = [self.pgp sign:signatureData usingKey:keyToSign passphrase:@"passphrase" detached:YES error:nil];
    XCTAssertNotNil(signature);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/62
- (void)testIssue62 {
    let keys = [self importKeysFromFile:@"issue62-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let data = [NSData dataWithContentsOfFile:[self.bundle pathForResource:@"issue62-message" ofType:@"asc"]];
    NSError *error;
    let decryptedData = [self.pgp decrypt:data passphrase:nil error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(decryptedData);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/59
- (void)testIssue59 {
    let keys = [PGPTestUtils keysFromFile:@"issue59-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

@end
