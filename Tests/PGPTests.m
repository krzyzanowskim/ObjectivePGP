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
#import <ObjectivePGP/PGPPartialKey+Private.h>
#import <ObjectivePGP/PGPSignaturePacket.h>
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

@property (nonatomic, readonly) NSBundle *bundle;

@end

@implementation ObjectivePGPTests

- (void)setUp {
    [super setUp];

    _bundle = PGPTestUtils.filesBundle;
}

- (void)tearDown {
    [super tearDown];
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

    let importedKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData error:nil];
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

    let importedPublicKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData error:nil];
    XCTAssert(importedPublicKeys.count == 1);

    let importedSecretKeys = [ObjectivePGP readKeysFromData:exportedPublicKeyData error:nil];
    XCTAssert(importedSecretKeys.count == 1);
}

- (void)testNotDuplicates {
    let keyring1 = [[PGPKeyring alloc] init];
    [keyring1 importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-plaintext.gpg"]];
    NSUInteger count1 = keyring1.keys.count;

    let keyring2 = [[PGPKeyring alloc] init];
    [keyring2 importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-plaintext.gpg"]];
    NSUInteger count2 = keyring2.keys.count;

    XCTAssertEqual(count1, count2);
}

- (void)testKeyEquality {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-plaintext.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-encrypted.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-plaintext.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];
    let encryptedKey = [keyring findKeyWithIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(encryptedKey);
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    NSError *error;

    let decryptedKey = [encryptedKey decryptedWithPassphrase:@"1234" error:&error];
    XCTAssertFalse(decryptedKey.isEncryptedWithPassword);
    XCTAssertNotNil(decryptedKey);
    let decryptedKey2 = [encryptedKey decryptedWithPassphrase:@"12345" error:&error];
    XCTAssertTrue(encryptedKey.isEncryptedWithPassword);
    XCTAssertNil(decryptedKey2);

    XCTAssertTrue([keyring.keys containsObject:encryptedKey]);
}


- (void)testExportImport {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-plaintext.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-encrypted.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-plaintext.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];

    XCTAssertNotNil(keyring.keys.firstObject);
    NSUInteger keysCount = keyring.keys.count;

    for (PGPKey *key in keyring.keys) {
        let exportedKeyData = [key export:nil];
        let readKeys = [ObjectivePGP readKeysFromData:exportedKeyData error:nil];
        XCTAssertTrue(readKeys.count == 1);
        [keyring importKeys:readKeys];
    }

    XCTAssertEqual(keyring.keys.count, keysCount);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/22
- (void)testIssue22 {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"issue22-original.asc"]];
    let key = [keyring.keys firstObject];

    NSError *err = nil;
    PGPPartialKey * _Nullable decryptedKey = [key.secretKey decryptedWithPassphrase:@"weakpassphrase" error:&err];
    XCTAssertNotNil(decryptedKey);
    NSData *exportedKeyData = [decryptedKey export:nil];
    XCTAssertEqual(exportedKeyData.length, (NSUInteger)4869);
    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);
}

- (void)testIssue35 {
    let messagePath = [PGPTestUtils pathToBundledFile:@"issue35-message.asc"];
    let keys = [PGPTestUtils readKeysFromPath:@"issue35-key.asc"];
    NSError *error = nil;
    [ObjectivePGP decrypt:[NSData dataWithContentsOfFile:messagePath] andVerifySignature:YES usingKeys:keys passphraseForKey:nil error:&error];
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/53
- (void)testIssue53GNUDummyS2K {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"issue53-s2k-gnu-dummy.prv.asc"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"issue53-s2k-gnu-dummy.pub.asc"]];
    XCTAssertTrue(keyring.keys.count > 0);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/44
- (void)testIssue44 {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"issue44-keys.asc"]];

    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);

    let keyToSign = [keyring findKeyWithIdentifier:@"71180E514EF122E5"];
    XCTAssertNotNil(keyToSign);

    let signatureData = [NSData dataWithContentsOfFile:[PGPTestUtils pathToBundledFile:@"issue44-keys.asc"]];
    let signature = [ObjectivePGP sign:signatureData detached:YES usingKeys:@[keyToSign] passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"passphrase"; } error:nil];
    XCTAssertNotNil(signature);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/62
- (void)testIssue62 {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"issue62-keys.asc"]];
    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);

    let data = [NSData dataWithContentsOfFile:[PGPTestUtils pathToBundledFile:@"issue62-message.asc"]];
    NSError *decryptError1;
    let decryptedData1 = [ObjectivePGP decrypt:data andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:nil error:&decryptError1];
    XCTAssertNotNil(decryptedData1);
    XCTAssertNotNil(decryptError1);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/59
- (void)testIssue59 {
    let keys = [PGPTestUtils readKeysFromPath:@"issue59-keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

- (void)testIssue77EncryptionKey {
    let keyring = [[PGPKeyring alloc] init];
    let generator = [[PGPKeyGenerator alloc] init];
    let key = [generator generateFor:@"marcin77@example.com" passphrase:@"test"];
    NSError *err;
    let publicKeyData = [key export:PGPKeyTypePublic error:&err];
    let secretKeyData = [key export:PGPKeyTypeSecret error:&err];

    let publicKeys = [ObjectivePGP readKeysFromData:publicKeyData error:nil];
    let secretKeys = [ObjectivePGP readKeysFromData:secretKeyData error:nil];
    [keyring importKeys:@[publicKeys.firstObject, secretKeys.firstObject]];

    let message = [@"test message" dataUsingEncoding:NSUTF8StringEncoding];

    NSError *encryptError;
    let encryptedMessage = [ObjectivePGP encrypt:message addSignature:NO usingKeys:publicKeys passphraseForKey:nil error:&encryptError];
    XCTAssertNil(encryptError);

    NSError *decryptError1;
    let decryptedMessage1 = [ObjectivePGP decrypt:encryptedMessage andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:nil error:&decryptError1];
    XCTAssertNotNil(decryptError1);
    XCTAssertEqualObjects(decryptedMessage1, nil);


    NSError *decryptError2;
    let decryptedMessage2 = [ObjectivePGP decrypt:encryptedMessage andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"test"; } error:&decryptError2];
    XCTAssertEqualObjects(decryptedMessage2, message);
}

- (void)testIssue82KeysEquality {
    let keys1 = [PGPTestUtils readKeysFromPath:@"issue82-keys.asc"];
    let keys2 = [PGPTestUtils readKeysFromPath:@"issue82-keys.asc"];
    XCTAssertEqualObjects(keys1, keys2);
}

- (void)testIssue88VerifyFromThunderbird {
    let keyring = [[PGPKeyring alloc] init];

    let pubKeys = [PGPTestUtils readKeysFromPath:@"issue88-pub.asc"];
    let secKeys = [PGPTestUtils readKeysFromPath:@"issue88-sec.asc"];

    [keyring importKeys:pubKeys];
    [keyring importKeys:secKeys];

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue88-message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    NSError *verifyError = nil;
    BOOL verified = [ObjectivePGP verify:messageData withSignature:nil usingKeys:keyring.keys passphraseForKey:nil error:&verifyError];
    XCTAssertNil(verifyError);
    XCTAssertTrue(verified);

    NSError *decryptError = nil;
    let decrypted = [ObjectivePGP decrypt:messageData andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:nil error:&decryptError];
    // let txt = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    XCTAssertNotNil(decrypted);
    XCTAssertNil(decryptError);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/84
// Embedded signatures code seems to have broken reading keys
- (void)testIssue84EmbeddedSignatures {
    // Input data is broken. Embeded signature has invalid data, ignore and load key anyway.
    let keys = [PGPTestUtils readKeysFromPath:@"issue84-key.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
}

// Symmetrically Encrypted Data Packet (Tag 9)
- (void)testIssue91Tag9 {
    let keyring = [[PGPKeyring alloc] init];
    let pubKeys = [PGPTestUtils readKeysFromPath:@"issue91-pub.asc"];
    let secKeys = [PGPTestUtils readKeysFromPath:@"issue91-sec.asc"];

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue91-message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];

    [keyring importKeys:pubKeys];
    [keyring importKeys:secKeys];
    NSError *decryptError = nil;
    let decrypted = [ObjectivePGP decrypt:messageData andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"abcd"; } error:&decryptError];
    XCTAssertNotNil(decrypted);
    XCTAssertNotNil(decryptError); // not signed
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/93
// Public Key is invalid input data but key works in android bouncycastle
// Armor checksum is optional.
- (void)testIssue93OptionalChecksum {
    let keys1 = [PGPTestUtils readKeysFromPath:@"issue93-keys1.asc"];
    XCTAssertEqual(keys1.count, (NSUInteger)1);
    let keys2 = [PGPTestUtils readKeysFromPath:@"issue93-keys2.asc"];
    XCTAssertEqual(keys2.count, (NSUInteger)1);
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
    
    let keys = [PGPTestUtils readKeysFromPath:@"sub-signing-key.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
    
    NSError* error = nil;
    let data = [@"Hello World!" dataUsingEncoding:NSUTF8StringEncoding];
    let signature = [ObjectivePGP sign:data detached:NO usingKeys:keys passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"12345678"; } error:&error];
    XCTAssertNotNil(signature, @"Signing failed: %@", error);
}

- (void)testVerificationCase1 {
    let keys = [PGPTestUtils readKeysFromPath:@"verification-test1-keys.asc"];
    let signaturePath = [PGPTestUtils pathToBundledFile:@"verification-test1-signature.asc"];
    let signatureData = [NSData dataWithContentsOfFile:signaturePath];

    NSError* error = nil;
    BOOL verified = [ObjectivePGP verifySignature:signatureData usingKeys:keys passphraseForKey:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(verified);

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

- (void)testSymmetricKeyEncryptedMessageMDC {
    // AES
    let messagePath = [PGPTestUtils pathToBundledFile:@"symmetric-message1.gpg"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    NSError *decryptError = nil;

    let decrypted = [ObjectivePGP decrypt:messageData andVerifySignature:YES usingKeys:@[] passphraseForKey:^NSString * _Nullable(PGPKey * _Nullable k) { return @"1234"; } error:&decryptError];
    XCTAssertNotNil(decrypted);
    XCTAssertEqualObjects(decrypted, [@"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent commodo cursus magna, vel scelerisque nisl consectetur et. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus." dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testSymmetricKeyEncryptedMessageTwofish {
    // TwoFish
    let messagePath = [PGPTestUtils pathToBundledFile:@"symmetric-message2.gpg"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    NSError *decryptError = nil;

    let decrypted = [ObjectivePGP decrypt:messageData andVerifySignature:YES usingKeys:@[] passphraseForKey:^NSString * _Nullable(PGPKey * _Nullable k) { return @"1234"; } error:&decryptError];
    XCTAssertNotNil(decrypted);
    XCTAssertEqualObjects(decrypted, [@"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent commodo cursus magna, vel scelerisque nisl consectetur et. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus." dataUsingEncoding:NSUTF8StringEncoding]);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/99
- (void)testIssue99OpenPGP_CFB {
    let keyring = [[PGPKeyring alloc] init];
    let pubKeys = [PGPTestUtils readKeysFromPath:@"issue99/public.asc"];
    let secKeys = [PGPTestUtils readKeysFromPath:@"issue99/private.asc"];
    [keyring importKeys:pubKeys];
    [keyring importKeys:secKeys];

    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue99/message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    XCTAssertNotNil(messageData);

    NSError *decryptError;
    let decryptedData = [ObjectivePGP decrypt:messageData andVerifySignature:NO usingKeys:keyring.keys passphraseForKey:^NSString * _Nullable(PGPKey * _Nullable key) {
        return @"abcd";
    } error:&decryptError];

    XCTAssertNil(decryptError);
    XCTAssertNotNil(decryptedData);

    let decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(decryptedString, @"Test\n-- Sent from my Android device with Secure Email.\n");
}

// PGPSymmetricallyEncryptedDataPacket
- (void)testIssue99OpenPGP_CFB_readPacketsFromData {
    let keyring = [[PGPKeyring alloc] init];
    let pubKeys = [PGPTestUtils readKeysFromPath:@"issue99-2/public.asc"];
    let secKeys = [PGPTestUtils readKeysFromPath:@"issue99-2/private.asc"];
    [keyring importKeys:pubKeys];
    [keyring importKeys:secKeys];

    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue99-2/message.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];
    XCTAssertNotNil(messageData);

    NSError *decryptError;
    let decryptedData = [ObjectivePGP decrypt:messageData andVerifySignature:NO usingKeys:keyring.keys passphraseForKey:^NSString * _Nullable(PGPKey * _Nullable key) {
        return @"abcd";
    } error:&decryptError];

    XCTAssertNil(decryptError);
    XCTAssertNotNil(decryptedData);

    let decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(decryptedString, @"Hello\n-- Sent from my Android device with Secure Email.\n");
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/102
- (void)testMemoryUsageIssue102 {
    // Temp large file
    let filePath = [PGPTestUtils pathToBundledFile:@"LargeFile.pdf"];
    let plaintextData = [NSData dataWithContentsOfFile:filePath];

    let generator = [[PGPKeyGenerator alloc] init];
    let key = [generator generateFor:@"test+mem@example.com" passphrase:nil];

    // encrypt data
    [ObjectivePGP encrypt:plaintextData addSignature:NO usingKeys:@[key] passphraseForKey:nil error:nil];
}

- (void)testIssue113PrimaryUserID {
    // KeyMultipleUserIDsPublicUserID1Primary.asc
    let pubKey1 = [[PGPTestUtils readKeysFromPath:@"issue113/KeyMultipleUserIDsPublicUserID1Primary.asc"] firstObject];
    XCTAssertNotNil(pubKey1);
    let pubKey1PrimaryUser = pubKey1.publicKey.primaryUser;
    XCTAssertEqualObjects(pubKey1PrimaryUser.userID, @"UserID1 <userid1@key.de>");

    let pubKey2 = [[PGPTestUtils readKeysFromPath:@"issue113/KeyMultipleUserIDsPublicUserID2Primary.asc"] firstObject];
    XCTAssertNotNil(pubKey2);
    let pubKey2PrimaryUser = pubKey2.publicKey.primaryUser;
    XCTAssertEqualObjects(pubKey2PrimaryUser.userID, @"UserID2 <userid2@key.de>");

    let secKey1 = [[PGPTestUtils readKeysFromPath:@"issue113/KeyMultipleUserIDsSecretUserID1Primary.asc"] firstObject];
    XCTAssertNotNil(secKey1);
    let secKey1PrimaryUser = secKey1.publicKey.primaryUser;
    XCTAssertEqualObjects(secKey1PrimaryUser.userID, @"UserID1 <userid1@key.de>");

    let secKey2 = [[PGPTestUtils readKeysFromPath:@"issue113/KeyMultipleUserIDsSecretUserID2Primary.asc"] firstObject];
    XCTAssertNotNil(secKey2);
    let secKey2PrimaryUser = secKey2.publicKey.primaryUser;
    XCTAssertEqualObjects(secKey2PrimaryUser.userID, @"UserID2 <userid2@key.de>");
}

- (void)testDSAKeyIssue106 {
    let keys = [PGPTestUtils readKeysFromPath:@"issue106/keys.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);

    let messagePath = [PGPTestUtils pathToBundledFile:@"issue106/keys.asc"];
    let messageData = [NSData dataWithContentsOfFile:messagePath];

    NSError *error;
    let signedData = [ObjectivePGP sign:messageData detached:NO usingKeys:keys passphraseForKey:nil error:&error];
    XCTAssertNotNil(signedData);
    XCTAssertNil(error);

    let keysWithPassword = [PGPTestUtils readKeysFromPath:@"issue106/keys-abcd.asc"];
    XCTAssertEqual(keysWithPassword.count, (NSUInteger)1);

    NSError *error2;
    let signedData2 = [ObjectivePGP sign:messageData detached:NO usingKeys:keysWithPassword passphraseForKey:^NSString * _Nullable(PGPKey * _Nonnull key) {
        return @"abcd";
    } error:&error2];
    XCTAssertNotNil(signedData2);
    XCTAssertNil(error2);
}

- (void)testElgamal1 {
    let publicKeys = [PGPTestUtils readKeysFromPath:@"elgamal/elgamal-key1.asc"];
    XCTAssertEqual(publicKeys.count, (NSUInteger)1);
    let secretKeys = [PGPTestUtils readKeysFromPath:@"elgamal/elgamal-key1-secret.asc"];
    XCTAssertEqual(secretKeys.count, (NSUInteger)1);

    let messagePath = [PGPTestUtils pathToBundledFile:@"elgamal/elgamal-key1.asc"];
    let plaintextData = [NSData dataWithContentsOfFile:messagePath];

    NSError *encryptError;
    NSData *encData = [ObjectivePGP encrypt:plaintextData addSignature:NO usingKeys:publicKeys passphraseForKey:nil error:&encryptError];
    XCTAssertNotNil(encData);
    XCTAssertNil(encryptError, @"Encryption failed");

    NSError *decryptError;
    let decData = [ObjectivePGP decrypt:encData andVerifySignature:NO usingKeys:secretKeys passphraseForKey:nil error:&decryptError];
    XCTAssertNotNil(decData);
    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void)testElgamal2 {
    let publicKeys = [PGPTestUtils readKeysFromPath:@"elgamal/elgamal-key2.asc"];
    XCTAssertEqual(publicKeys.count, (NSUInteger)1);
    let secretKeys = [PGPTestUtils readKeysFromPath:@"elgamal/elgamal-key2-secret.asc"];
    XCTAssertEqual(secretKeys.count, (NSUInteger)1);

    let messagePath = [PGPTestUtils pathToBundledFile:@"elgamal/elgamal-key2.asc"];
    let plaintextData = [NSData dataWithContentsOfFile:messagePath];

    NSError *encryptError;
    NSData *encData = [ObjectivePGP encrypt:plaintextData addSignature:NO usingKeys:publicKeys passphraseForKey:nil error:&encryptError];
    XCTAssertNotNil(encData);
    XCTAssertNil(encryptError, @"Encryption failed");

    NSError *decryptError;
    let decData = [ObjectivePGP decrypt:encData andVerifySignature:NO usingKeys:secretKeys passphraseForKey:^NSString * _Nullable(PGPKey * _Nonnull key) {
        return @"elgamal";
    } error:&decryptError];
    XCTAssertNotNil(decData);
    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void)testElgamal3 {
    // Missing keys flags. Use conventions.
    let keys = [PGPTestUtils readKeysFromPath:@"elgamal/E5ED9F41.asc"];
    XCTAssertEqual(keys.count, (NSUInteger)1);
    NSError *error = nil;
    NSData *encrypted = [ObjectivePGP encrypt:NSData.new addSignature:false usingKeys:keys passphraseForKey:nil error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(encrypted);
}

/// https://github.com/krzyzanowskim/ObjectivePGP/issues/130
- (void)testExpirationDate {
    let key = [PGPTestUtils readKeysFromPath:@"issue130-espirationdate.asc"][0];
    let expirationDate = key.expirationDate;
    XCTAssertNotNil(expirationDate);
    XCTAssertEqual(expirationDate.timeIntervalSince1970, 1607687539); // Fri Dec 11 11:52:20 2020 UTC
}

- (void)testMalformedHeaderIssue144 {
  let message = [@"€" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertNotNil(message);
  [ObjectivePGP readKeysFromData:message error:nil];
}

- (void)testExpirationDateIssue146 {
  let key = [[PGPTestUtils readKeysFromPath:@"issue146/keys.asc"] firstObject];
  XCTAssertNotNil(key);
  let users = [[key publicKey] users];
  XCTAssertEqual(users.count, 2);
  XCTAssertNotNil(key.expirationDate);
  XCTAssertEqual(key.expirationDate.timeIntervalSince1970, 1610412042); // Tue Jan 12 01:40:42 2021 CET
}

- (void)testECCPublicKeyImportIssue141 {
    let eccPub = [PGPTestUtils readKeysFromPath:@"issue141/eccPublicKey.asc"];
    XCTAssertEqual(eccPub.count, 1);
    let rsaPub = [PGPTestUtils readKeysFromPath:@"issue141/rsaPublicKey.asc"];
    XCTAssertEqual(rsaPub.count, 1);
}

- (void)testECCSecretKeyImportIssue141 {
    let eccSec = [PGPTestUtils readKeysFromPath:@"issue141/eccSecretKey.asc"];
    XCTAssertEqual(eccSec.count, 1);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/158#issuecomment-533493519
- (void)testMainKeyEncryptionIssue158 {
  let publicKey = [[PGPTestUtils readKeysFromPath:@"issue158/pubkey.asc"] firstObject];
  XCTAssertNotNil(publicKey);
  XCTAssertNotNil(publicKey.publicKey.primaryUserSelfCertificate);
  XCTAssertTrue(publicKey.publicKey.primaryUserSelfCertificate.canBeUsedToEncrypt);
  let secretKeys = [PGPTestUtils readKeysFromPath:@"issue158/privkey.asc"];
  XCTAssertEqual(secretKeys.count, (NSUInteger)1);

  let data = [@"Hello, I'm here !" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *encryptError = nil;
  let encryptedData = [ObjectivePGP encrypt:data addSignature:NO usingKeys:@[publicKey] passphraseForKey:nil error:&encryptError];
  XCTAssertNil(encryptError);
  XCTAssertNotNil(encryptedData);

  let armoredEntryptedData = [PGPArmor armored:encryptedData as:PGPArmorMessage];
  XCTAssertNotNil(armoredEntryptedData);
  NSLog(@"%@",armoredEntryptedData);
  XCTAssertGreaterThan(armoredEntryptedData.length, 234);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/166
- (void)testArmoredMessageIssue166 {
    let keys = [PGPTestUtils readKeysFromPath:@"issue166/key.asc"];
    XCTAssertNotNil(keys);
    XCTAssertEqual(keys.count, 1);
}

// https://github.com/krzyzanowskim/ObjectivePGP/issues/118
- (void)testReadEdDSASignatureIssue118 {
    let key = [[PGPTestUtils readKeysFromPath:@"issue118-key.asc"] firstObject];
    XCTAssertNotNil(key.publicKey);
    XCTAssertNil(key.secretKey);
    XCTAssertNotNil(key);
}

- (void)testECC_decrypt1 {
    let keyPub = [[PGPTestUtils readKeysFromPath:@"ecc-curve25519-pub1.asc"] firstObject];
    XCTAssertNotNil(keyPub);
    XCTAssertEqualObjects(keyPub.keyID.longIdentifier, @"753EC78567FE1231");

    let keySec = [[PGPTestUtils readKeysFromPath:@"ecc-curve25519-sec1.asc"] firstObject];
    XCTAssertNotNil(keySec);
    XCTAssertEqualObjects(keySec.keyID.longIdentifier, @"753EC78567FE1231");

    // $ echo "test message" | gpg2 --armor --encrypt --recipient "Test ECC"
    let encryptedMessage = @"-----BEGIN PGP MESSAGE-----\n\
\n\
hF4D4gFobDLlEAwSAQdA5IBiZ407PLrCbB9+IeQA9VUD7hfnZ1i8wkIhmTYtDA0w\n\
BOico4LzPq63CGDjyD9tvYiuASWvrq9O5CEqhsIFaiZLnWIqmHMvEED8g8RKmaez\n\
0kgBC2Orf6Y9B3xREBysBJk6K/3BPenIoBg/h3WBB7BuSrB2ldc2PSVq+L0/b9hw\n\
9DHsx4lll4fSzhq0MWD6NtEWZ7nPapRGLgY=\n\
=60RH\n\
-----END PGP MESSAGE-----";

    let decrypted = [ObjectivePGP decrypt:[encryptedMessage dataUsingEncoding:NSUTF8StringEncoding] andVerifySignature:NO usingKeys:@[keySec] passphraseForKey:nil error:nil];
    XCTAssertNotNil(decrypted);
    let decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(decryptedString, @"test message");
}

- (void)testECC_decrypt2 {
    let privateKey = [@"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
xVgEX8+jfBYJKwYBBAHaRw8BAQdA9GbdDjprR0sWf0R5a5IpulUauc0FsmzJ\
mOYCfoowt8EAAP9UwaqC0LWWQ5RlX7mps3728vFa/If1KBVwAjk7Uqhi2BKL\
zQ90ZXN0MiA8YkBhLmNvbT7CjAQQFgoAHQUCX8+jfAQLCQcIAxUICgQWAgEA\
AhkBAhsDAh4BACEJEG464aV2od77FiEEIcg441MtKnyJnPDRbjrhpXah3vuR\
gQD+Il6Gw2oIok4/ANyDDLBYZtKqRrMv4NcfF9DHYuAFcP4BAPhFOffyP3qU\
AEZb7QPrWdLfhn8/FeSFZxJvnmupQ9sDx10EX8+jfBIKKwYBBAGXVQEFAQEH\
QOSzo9cX1U2esGFClprOt0QWXNJ97228R5tKFxo6/0NoAwEIBwAA/0n4sq2i\
N6/jE+6rVO4o/7LW0xahxpV1tTA6qv1Op9TwFIDCeAQYFggACQUCX8+jfAIb\
DAAhCRBuOuGldqHe+xYhBCHIOONTLSp8iZzw0W464aV2od773XcA/jlmX8/c\
1/zIotEkyMZB4mI+GAg3FQ6bIACFBH1sz0MzAP9Snri0P4FRZ8D5THRCJoUm\
GBgpBmrf6IVv484jBswGDA==\n\
=8rBO\n\
-----END PGP PRIVATE KEY BLOCK-----" dataUsingEncoding:NSUTF8StringEncoding];
    let keys = [ObjectivePGP readKeysFromData:privateKey error:nil];
    XCTAssertNotNil(keys);
    XCTAssertEqual(keys.count, 1);

    let encrypted = [@"-----BEGIN PGP MESSAGE-----\n\
\n\
wV4DWlRRjuYiLSsSAQdAWwDKQLN4ZUS5fqiwFtAMrRfZZe9J4SgClhG6avEe\
AEowkSZwWRT+8Hy8aBIb4oPehYUFXXZ7BtlJCyd7LOTUtqyc00OE0721PC3M\
v0+zird60sACATlDmTwweR5GFtEAjHVheIL5rbkOBRD+oSqB8z+IovNg83Pz\
FVwsFZnCLtECoYgpF2MJdopuC/bPHcrvf4ndwmD11uXtms4Rq4y25QyqApbn\
Hj/hljufk0OkavUXxrNKjGQtxLHMpa3Nsi0MHWY8JguxOKFKpAIMP32CD1e+\
j+GItrR+QbbN13ODlcR3hf66cwjLLsJCx5VcBaRspKF05O3ix/u9KVjJqtbi\
Ie6jnY0zP2ldtS4JmhKBa43qmOHCxHc=\n\
=7B58\n\
-----END PGP MESSAGE-----" dataUsingEncoding:NSUTF8StringEncoding];

    let decrypted = [ObjectivePGP decrypt:encrypted andVerifySignature:NO usingKeys:keys passphraseForKey:nil error:nil];
    XCTAssertNotNil(decrypted);
    let decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(decryptedString, @"hello");
}

- (void)testECC_encrypt1 {
    let keyPub = [[PGPTestUtils readKeysFromPath:@"ecc-curve25519-pub1.asc"] firstObject];
    XCTAssertNotNil(keyPub);
    XCTAssertEqualObjects(keyPub.keyID.longIdentifier, @"753EC78567FE1231");

    let keySec = [[PGPTestUtils readKeysFromPath:@"ecc-curve25519-sec1.asc"] firstObject];
    XCTAssertNotNil(keySec);
    XCTAssertEqualObjects(keySec.keyID.longIdentifier, @"753EC78567FE1231");

    let data = [@"test message" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *encryptError;
    let encryptedData = [ObjectivePGP encrypt:data addSignature:NO usingKeys:@[keyPub] passphraseForKey:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);

    let decrypted = [ObjectivePGP decrypt:encryptedData andVerifySignature:NO usingKeys:@[keyPub, keySec] passphraseForKey:nil error:nil];
    XCTAssertNil(decrypted);

}


@end
