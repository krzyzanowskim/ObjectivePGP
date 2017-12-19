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
    return [PGPTestUtils readKeysFromFile:fileName];
}

- (void)tearDown {
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
    self.pgp = nil;
}

- (void)testLoadKeys {
    let keyring = [[PGPKeyring alloc] init];
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys];
    XCTAssert(keyring.keys.count == 1, @"Should load 1 key");

    let foundKeys1 = [keyring findKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys1.count == 1);

    let foundKeys2 = [keyring findKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys2.count == 0);

    let key = [keyring findKeyWithIdentifier:@"952E4E8B"];
    XCTAssertNotNil(key, @"Key 952E4E8B not found");
}

- (void)testSaveSecretKeys {
    let keyring = [[PGPKeyring alloc] init];
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys];
    XCTAssertTrue(keyring.keys.count > 0);

    // Save to file
    NSError *saveError = nil;
    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
    XCTAssertTrue([keyring exportKeysOfType:PGPKeyTypeSecret toFile:exportSecretKeyringPath error:&saveError]);
    XCTAssertNil(saveError);

    // Check if can be loaded
    let checkkeyring = [[PGPKeyring alloc] init];
    let checkKeys = [ObjectivePGP readKeysFromFile:exportSecretKeyringPath];
    [checkkeyring importKeys:checkKeys];
    XCTAssertTrue(checkKeys.count > 0);

    XCTAssert(keyring.keys.count > 0, @"Keys not loaded");

    let key = checkkeyring.keys.firstObject;
    XCTAssertFalse(key.isEncryptedWithPassword, @"Should not be encrypted");
    XCTAssertEqualObjects([key.keyID longIdentifier], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void)testSavePublicKeys {
    let keyring = [[PGPKeyring alloc] init];
    let keys = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys];
    XCTAssertTrue(keyring.keys.count > 0);

    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];

    NSError *psaveError = nil;
    XCTAssertTrue([keyring exportKeysOfType:PGPKeyTypePublic toFile:exportPublicKeyringPath error:&psaveError]);
    XCTAssertNil(psaveError);

    NSLog(@"Created file %@", exportPublicKeyringPath);
}

- (void)testPrimaryKey {
    let keyring = [[PGPKeyring alloc] init];
    let keys = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys];
    XCTAssertTrue(keyring.keys.count > 0);

    let key = keyring.keys.firstObject;
    XCTAssertFalse(key.isEncryptedWithPassword, @"Should not be encrypted");
    XCTAssertEqualObjects([key.keyID longIdentifier], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void)testSigning {
    let keyring = [[PGPKeyring alloc] init];
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys2];

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    let secKeyringPath = [self.bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    BOOL status = [[NSFileManager defaultManager] copyItemAtPath:secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    let keyToSign = [keyring findKeyWithIdentifier:@"25A233C2952E4E8B"];
    XCTAssertNotNil(keyToSign);
    let dataToSign = [NSData dataWithContentsOfFile:fileToSignPath];

    // detached signature
    NSError *signatureError = nil;
    NSData *signatureData = [ObjectivePGP sign:dataToSign detached:YES usingKeys:@[keyToSign] passphraseForKey:nil error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    let keyToValidateSign = [keyring findKeyWithIdentifier:@"25A233C2952E4E8B"];
    NSError *verifyError = nil;
    status = [ObjectivePGP verify:dataToSign withSignature:signatureData usingKeys:@[keyToValidateSign] passphraseForKey:nil error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);

    // Signed data
    NSData *signedData = [ObjectivePGP sign:dataToSign detached:NO usingKeys:@[keyToSign] passphraseForKey:nil error:&signatureError];
    XCTAssertNotNil(signedData);
    XCTAssertNil(signatureError);

    NSString *signedPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin.sig"];
    status = [signedData writeToFile:signedPath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    status = [ObjectivePGP verify:signedData withSignature:nil usingKeys:keyring.keys passphraseForKey:nil error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);
}

#define PLAINTEXT @"Plaintext: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse blandit justo eros.\n"

- (void)testEncryption {
    let keyring = [[PGPKeyring alloc] init];
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys2];

    // Public key
    let keyToEncrypt = [keyring findKeyWithIdentifier:@"25A233C2952E4E8B"];

    XCTAssertNotNil(keyToEncrypt);

    NSData *plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [ObjectivePGP encrypt:plainData addSignature:NO usingKeys:@[keyToEncrypt] passphraseForKey:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);

    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [ObjectivePGP decrypt:encryptedData usingKeys:keyring.keys passphraseForKey:nil verifySignature:YES error:nil];
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");

    // ARMORED
    NSData *encryptedDataArmored = [ObjectivePGP encrypt:plainData addSignature:NO usingKeys:@[keyToEncrypt] passphraseForKey:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedDataArmored);

    NSString *fileEncryptedArmored = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted.armored"];
    status = [encryptedDataArmored writeToFile:fileEncryptedArmored atomically:YES];
    XCTAssertTrue(status);
}

- (void)testGPGEncryptedMessage {
    let keyring = [[PGPKeyring alloc] init];
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys2];

    NSError *error = nil;
    NSString *encryptedPath = [PGPTestUtils pathToBundledFile:@"secring-test-plaintext-encrypted-message.asc"];
    [ObjectivePGP decrypt:[NSData dataWithContentsOfFile:encryptedPath] usingKeys:keyring.keys passphraseForKey:nil verifySignature:YES error:&error];
}

- (void)testEncryptWithMultipleRecipients {
    let keyring = [[PGPKeyring alloc] init];
    let keys1 = [self loadKeysFromFile:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys1];

    let keys2 = [self loadKeysFromFile:@"secring-test-plaintext.gpg"];
    [keyring importKeys:keys2];

    // Public key
    let keyToEncrypt2 = [keyring findKeyWithIdentifier:@"66753341"];
    let keyToEncrypt1 = [keyring findKeyWithIdentifier:@"952E4E8B"];

    XCTAssertNotNil(keyToEncrypt1);
    XCTAssertNotNil(keyToEncrypt2);

    NSData *plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [ObjectivePGP encrypt:plainData addSignature:NO usingKeys:@[keyToEncrypt1, keyToEncrypt2] passphraseForKey:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);

    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.multiple.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [ObjectivePGP decrypt:encryptedData usingKeys:keyring.keys passphraseForKey:nil verifySignature:YES error:&encryptError];
    XCTAssertNotNil(encryptError);
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");
}
@end
