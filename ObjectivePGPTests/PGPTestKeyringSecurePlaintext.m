//
//  ObjectivePGPTestSecurePlaintext.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPMacros.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPUser.h"
#import "PGPMacros+Private.h"
#import "PGPTestUtils.h"
#import <XCTest/XCTest.h>

@interface ObjectivePGPTestKeyringSecurePlaintext : XCTestCase
@property (nonatomic, readonly) NSString *workingDirectory;
@property (nonatomic, nullable) ObjectivePGP *pgp;
@property (nonatomic, readonly) NSBundle *bundle;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp {
    [super setUp];

    _bundle = PGPTestUtils.filesBundle;
    _pgp = [[ObjectivePGP alloc] init];

    NSString *newDir = [@"ObjectivePGPTests" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }
    _workingDirectory = tmpDirectoryPath;

    // copy keyring to verify
    let secKeyringPath = [self.bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    let pubKeyringPath = [self.bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    [[NSFileManager defaultManager] copyItemAtPath:secKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[secKeyringPath lastPathComponent]] error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:pubKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[pubKeyringPath lastPathComponent]] error:nil];
}

- (NSArray<PGPKey *> *)loadKeysFromFile:(NSString *)fileName {
    let path = [self.bundle pathForResource:fileName.stringByDeletingPathExtension ofType:fileName.pathExtension];
    return [self.pgp keysFromFile:path];
}

- (void)tearDown {
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
    self.pgp = nil;
}

- (void)testLoadKeys {
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys];
    XCTAssert(self.pgp.keys.count == 1, @"Should load 1 key");

    let foundKeys1 = [self.pgp findKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys1.count == 1);

    let foundKeys2 = [self.pgp findKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys2.count == 0);

    let key = [self.pgp findKeyWithIdentifier:@"952E4E8B"];
    XCTAssertNotNil(key, @"Key 952E4E8B not found");
}

- (void)testSaveSecretKeys {
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys];
    XCTAssertTrue(self.pgp.keys.count > 0);

    // Save to file
    NSError *saveError = nil;
    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
    XCTAssertTrue([self.pgp exportKeysOfType:PGPPartialKeySecret toFile:exportSecretKeyringPath error:&saveError]);
    XCTAssertNil(saveError);

    // Check if can be loaded
    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
    let checkKeys = [checkPGP keysFromFile:exportSecretKeyringPath];
    [checkPGP importKeys:checkKeys];
    XCTAssertTrue(checkKeys.count > 0);

    XCTAssert(self.pgp.keys.count > 0, @"Keys not loaded");

    let key = checkPGP.keys.firstObject;
    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertFalse(key.secretKey.isEncryptedWithPassword, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longIdentifier], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void)testSavePublicKeys {
    let keys = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys];
    XCTAssertTrue(self.pgp.keys.count > 0);

    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];

    NSError *psaveError = nil;
    XCTAssertTrue([self.pgp exportKeysOfType:PGPPartialKeyPublic toFile:exportPublicKeyringPath error:&psaveError]);
    XCTAssertNil(psaveError);

    NSLog(@"Created file %@", exportPublicKeyringPath);
}

- (void)testPrimaryKey {
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys];
    XCTAssertTrue(self.pgp.keys.count > 0);

    let key = self.pgp.keys.firstObject;
    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertFalse(key.secretKey.isEncryptedWithPassword, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longIdentifier], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void)testSigning {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys2];

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    let secKeyringPath = [self.bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    BOOL status = [[NSFileManager defaultManager] copyItemAtPath:secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    let keyToSign = [self.pgp findKeyWithIdentifier:@"25A233C2952E4E8B"];
    XCTAssertNotNil(keyToSign);
    let dataToSign = [NSData dataWithContentsOfFile:fileToSignPath];

    // detached signature
    NSError *signatureError = nil;
    NSData *signatureData = [self.pgp sign:dataToSign usingKey:keyToSign passphrase:nil detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    let keyToValidateSign = [self.pgp findKeyWithIdentifier:@"25A233C2952E4E8B"];
    NSError *verifyError = nil;
    status = [self.pgp verify:dataToSign withSignature:signatureData usingKey:keyToValidateSign error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);

    // Signed data
    NSData *signedData = [self.pgp sign:dataToSign usingKey:keyToSign passphrase:nil detached:NO error:&signatureError];
    XCTAssertNotNil(signedData);
    XCTAssertNil(signatureError);

    NSString *signedPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin.sig"];
    status = [signedData writeToFile:signedPath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    status = [self.pgp verify:signedData error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);
}

#define PLAINTEXT @"Plaintext: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse blandit justo eros.\n"

- (void)testEncryption {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys2];

    // Public key
    let keyToEncrypt = [self.pgp findKeyWithIdentifier:@"25A233C2952E4E8B"];

    XCTAssertNotNil(keyToEncrypt);

    NSData *plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.pgp encrypt:plainData usingKeys:@[keyToEncrypt] armored:NO error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);

    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [self.pgp decrypt:encryptedData passphrase:nil error:nil];
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");

    // ARMORED
    NSData *encryptedDataArmored = [self.pgp encrypt:plainData usingKeys:@[keyToEncrypt] armored:YES error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedDataArmored);

    NSString *fileEncryptedArmored = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted.armored"];
    NSLog(@"%@", fileEncryptedArmored);
    status = [encryptedDataArmored writeToFile:fileEncryptedArmored atomically:YES];
    XCTAssertTrue(status);
}

- (void)testGPGEncryptedMessage {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys2];

    NSError *error = nil;
    NSString *encryptedPath = [self.bundle pathForResource:@"secring-test-plaintext-encrypted-message" ofType:@"asc"];
    [self.pgp decrypt:[NSData dataWithContentsOfFile:encryptedPath] passphrase:nil error:&error];
}

- (void)testEncryptWithMultipleRecipients {
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [self.pgp importKeys:keys2];

    // Public key
    let keyToEncrypt2 = [self.pgp findKeyWithIdentifier:@"66753341"];
    let keyToEncrypt1 = [self.pgp findKeyWithIdentifier:@"952E4E8B"];

    XCTAssertNotNil(keyToEncrypt1);
    XCTAssertNotNil(keyToEncrypt2);

    NSData *plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.pgp encrypt:plainData usingKeys:@[keyToEncrypt1, keyToEncrypt2] armored:NO error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);

    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.multiple.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [self.pgp decrypt:encryptedData passphrase:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");
}
@end
