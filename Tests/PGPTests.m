//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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
    let keys = [PGPTestUtils readKeysFromFile:fileName];
    [self.pgp.defaultKeyring importKeys:keys];
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

    let sign = [ObjectivePGP sign:dataToSign detached:YES usingKeys:@[key] passphraseForKey:nil error:nil];
    XCTAssertNotNil(sign);

    BOOL isVerified = [ObjectivePGP verify:dataToSign withSignature:sign usingKeys:@[key] passphraseForKey:nil error:nil];
    XCTAssertTrue(isVerified);

    // test export
    let exportedPublicKeyData = [key export:PGPKeyTypePublic error:nil];
    XCTAssertNotNil(exportedPublicKeyData);
    let exportedSecretKeyData = [key export:PGPKeyTypeSecret error:nil];
    XCTAssertNotNil(exportedSecretKeyData);

    let importedKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData];
    XCTAssert(importedKeys.count == 1);
    XCTAssertEqualObjects(importedKeys.firstObject.keyID, key.keyID);
}

- (void)testGenerateNewKeyWithPassphrase {
    let keyGenerator = [[PGPKeyGenerator alloc] init];
    let key = [keyGenerator generateFor:@"Marcin <marcin@example.com>" passphrase:@"1234567890"];
    XCTAssertNotNil(key);

    let exportedPublicKeyData = [key export:PGPKeyTypePublic error:nil];
    XCTAssertNotNil(exportedPublicKeyData);
    let exportedSecretKeyData = [key export:PGPKeyTypeSecret error:nil];
    XCTAssertNotNil(exportedSecretKeyData);

    let importedPublicKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData];
    XCTAssert(importedPublicKeys.count == 1);

    let importedSecretKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData];
    XCTAssert(importedSecretKeys.count == 1);
}

- (void)testNotDuplicates {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    NSUInteger count1 = self.pgp.defaultKeyring.keys.count;

    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    NSUInteger count2 = self.pgp.defaultKeyring.keys.count;

    XCTAssertEqual(count1, count2);
}

- (void)testKeyEquality {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self importKeysFromFile:@"pubring-test-encrypted.gpg"];
    [self importKeysFromFile:@"secring-test-plaintext.gpg"];
    [self importKeysFromFile:@"secring-test-encrypted.gpg"];
    let encryptedKey = [self.pgp.defaultKeyring findKeyWithIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(encryptedKey);
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    NSError *error;

    let decryptedKey = [encryptedKey decryptedWithPassphrase:@"1234" error:&error];
    XCTAssertFalse(decryptedKey.isEncryptedWithPassword);
    XCTAssertNotNil(decryptedKey);
    let decryptedKey2 = [encryptedKey decryptedWithPassphrase:@"12345" error:&error];
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    XCTAssertNil(decryptedKey2);

    XCTAssertTrue([self.pgp.defaultKeyring.keys containsObject:encryptedKey]);
}


- (void)testExportImport {
    [self importKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self importKeysFromFile:@"pubring-test-encrypted.gpg"];
    [self importKeysFromFile:@"secring-test-plaintext.gpg"];
    [self importKeysFromFile:@"secring-test-encrypted.gpg"];

    XCTAssertNotNil(self.pgp.defaultKeyring.keys.firstObject);
    NSUInteger keysCount = self.pgp.defaultKeyring.keys.count;

    for (PGPKey *key in self.pgp.defaultKeyring.keys) {
        let exportedKeyData = [key export:nil];
        let readKeys = [ObjectivePGP readKeysFromData:exportedKeyData];
        XCTAssertTrue(readKeys.count == 1);
        [self.pgp.defaultKeyring importKeys:readKeys];
    }

    XCTAssertEqual(self.pgp.defaultKeyring.keys.count, keysCount);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/22
- (void)testIssue22 {
    [self importKeysFromFile:@"issue22-original.asc"];
    let key = [self.pgp.defaultKeyring.keys firstObject];

    NSError *err = nil;
    PGPPartialKey * _Nullable decryptedKey = [key.secretKey decryptedWithPassphrase:@"weakpassphrase" error:&err];
    XCTAssertNotNil(decryptedKey);
    NSData *exportedKeyData = [decryptedKey export:nil];
    XCTAssertEqual(exportedKeyData.length, (NSUInteger)4869);
    XCTAssertEqual(self.pgp.defaultKeyring.keys.count, (NSUInteger)1);
}

- (void)testIssue35 {
    let messagePath = [PGPTestUtils pathToBundledFile:@"issue35-message.asc"];
    let keys = [PGPTestUtils readKeysFromFile:@"issue35-key.asc"];
    NSError *error = nil;
    [ObjectivePGP decrypt:[NSData dataWithContentsOfFile:messagePath] usingKeys:keys passphraseForKey:nil verifySignature:YES error:&error];
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/53
- (void)testIssue53GNUDummyS2K {
    [self importKeysFromFile:@"issue53-s2k-gnu-dummy.prv.asc"];
    [self importKeysFromFile:@"issue53-s2k-gnu-dummy.pub.asc"];
    XCTAssertTrue(self.pgp.defaultKeyring.keys.count > 0);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/44
- (void)testIssue44 {
    let keys = [self importKeysFromFile:@"issue44-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let keyToSign = [self.pgp.defaultKeyring findKeyWithIdentifier:@"71180E514EF122E5"];
    XCTAssertNotNil(keyToSign);

    let signatureData = [NSData dataWithContentsOfFile:[PGPTestUtils pathToBundledFile:@"issue44-keys.asc"]];
    let signature = [ObjectivePGP sign:signatureData detached:YES usingKeys:@[keyToSign] passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"passphrase"; } error:nil];
    XCTAssertNotNil(signature);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/62
- (void)testIssue62 {
    let keys = [self importKeysFromFile:@"issue62-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let data = [NSData dataWithContentsOfFile:[PGPTestUtils pathToBundledFile:@"issue62-message.asc"]];
    NSError *decryptError1;
    let decryptedData1 = [ObjectivePGP decrypt:data usingKeys:keys passphraseForKey:nil verifySignature:YES error:&decryptError1];
    XCTAssertNotNil(decryptedData1);
    XCTAssertNotNil(decryptError1);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/59
- (void)testIssue59 {
    let keys = [PGPTestUtils readKeysFromFile:@"issue59-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

- (void)testIssue77EncryptionKey {
    let generator = [[PGPKeyGenerator alloc] init];
    let key = [generator generateFor:@"marcin77@example.com" passphrase:@"test"];
    NSError *err;
    let publicKeyData = [key export:PGPKeyTypePublic error:&err];
    let secretKeyData = [key export:PGPKeyTypeSecret error:&err];

    let pgp = [[ObjectivePGP alloc] init];
    let publicKeys = [ObjectivePGP readKeysFromData:publicKeyData];
    let secretKeys = [ObjectivePGP readKeysFromData:secretKeyData];
    [pgp.defaultKeyring importKeys:@[publicKeys.firstObject, secretKeys.firstObject]];

    let message = [@"test message" dataUsingEncoding:NSUTF8StringEncoding];

    NSError *encryptError;
    let encryptedMessage = [ObjectivePGP encrypt:message addSignature:NO usingKeys:publicKeys passphraseForKey:nil error:&encryptError];

    NSError *decryptError1;
    let decryptedMessage1 = [ObjectivePGP decrypt:encryptedMessage usingKeys:pgp.defaultKeyring.keys passphraseForKey:nil verifySignature:YES error:&decryptError1];
    XCTAssertEqualObjects(decryptedMessage1, nil);


    NSError *decryptError2;
    let decryptedMessage2 = [ObjectivePGP decrypt:encryptedMessage usingKeys:pgp.defaultKeyring.keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"test"; } verifySignature:YES error:&decryptError2];
    XCTAssertEqualObjects(decryptedMessage2, message);
}

- (void)testIssue82KeysEquality {
    let keys1 = [PGPTestUtils readKeysFromFile:@"issue82-keys.asc"];
    let keys2 = [PGPTestUtils readKeysFromFile:@"issue82-keys.asc"];
    XCTAssertEqualObjects(keys1, keys2);
}

- (void)testIssue88VerifyFromThunderbird {
    let pubKeys = [PGPTestUtils readKeysFromFile:@"issue88-pub.asc"];
    let secKeys = [PGPTestUtils readKeysFromFile:@"issue88-sec.asc"];

    let pgp = [ObjectivePGP new];
    [pgp.defaultKeyring importKeys:pubKeys];
    [pgp.defaultKeyring importKeys:secKeys];

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue88-message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    NSError *verifyError = nil;
    BOOL verified = [ObjectivePGP verify:messageData withSignature:nil usingKeys:pgp.defaultKeyring.keys passphraseForKey:nil error:&verifyError];
    XCTAssertNil(verifyError);
    XCTAssertTrue(verified);

    NSError *decryptError = nil;
    let decrypted = [ObjectivePGP decrypt:messageData usingKeys:pgp.defaultKeyring.keys passphraseForKey:nil verifySignature:YES error:&decryptError];
    // let txt = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    XCTAssertNotNil(decrypted);
    XCTAssertNil(decryptError);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/84
// Embedded signatures code seems to have broken reading keys
- (void)testIssue84EmbeddedSignatures {
    // Input data is broken. Embeded signature has invalid data, ignore and load key anyway.
    let keys = [PGPTestUtils readKeysFromFile:@"issue84-key.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

// Symmetrically Encrypted Data Packet (Tag 9)
- (void)testIssue91Tag9 {
    let pubKeys = [PGPTestUtils readKeysFromFile:@"issue91-pub.asc"];
    let secKeys = [PGPTestUtils readKeysFromFile:@"issue91-sec.asc"];

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue91-message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];

    let pgp = [ObjectivePGP new];
    [pgp.defaultKeyring importKeys:pubKeys];
    [pgp.defaultKeyring importKeys:secKeys];
    NSError *decryptError = nil;
    let decrypted = [ObjectivePGP decrypt:messageData usingKeys:pgp.defaultKeyring.keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"abcd"; } verifySignature:YES error:&decryptError];
    XCTAssertNotNil(decrypted);
    XCTAssertNotNil(decryptError); // not signed
}

- (void)testSigningSubKey {
    // subkey generated with GnuPG 2.1.18
    //
    // gpg --gen-key
    //      Test User <test@fake.workingcopyapp.com>
    //      passphrase: 12345678
    // gpg --edit-key test@fake.workingcopyapp.com
    //       addkey
    //       4: RSA (sign only)
    //       50 days expiration
    // gpg --list-signatures     # to get fingerprint
    // gpg --armor --export-secret-subkeys FA0D04B6D62865E5
    
    let keys = [PGPTestUtils readKeysFromFile:@"sub-signing-key.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
    
    NSError* error = nil;
    let data = [@"Hello World!" dataUsingEncoding:NSUTF8StringEncoding];
    let signature = [ObjectivePGP sign:data detached:NO usingKeys:keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"12345678"; } error:&error];
    XCTAssertNotNil(signature, @"Signing failed: %@", error);
}

- (void)testUserAttrributes {
    let generator = [[PGPKeyGenerator alloc] init];
    let key = [generator generateFor:@"marcin77@example.com" passphrase:@"test"];
    let user = key.publicKey.users.firstObject;

    let imagePath = [PGPTestUtils pathToBundledFile:@"jpeg.jpg"];
    user.image = [NSData dataWithContentsOfFile:imagePath];

    NSError *keyExportError;
    let exportedKey = [key export:&keyExportError];
    XCTAssertNotNil(exportedKey);
}

@end
