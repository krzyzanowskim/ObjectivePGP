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
@property (nonatomic) NSString *secKeyringPath;
@property (nonatomic) NSString *pubKeyringPath;
@property (nonatomic) NSString *workingDirectory;
@property (nonatomic) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSLog(@"%s", __PRETTY_FUNCTION__);

    self.oPGP = [[ObjectivePGP alloc] init];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.secKeyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.pubKeyringPath = [bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];

    NSString *newDir = [@"ObjectivePGPTests" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }
    self.workingDirectory = tmpDirectoryPath;
    
    // copy keyring to verify
    [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[self.secKeyringPath lastPathComponent]] error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:self.pubKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[self.pubKeyringPath lastPathComponent]] error:nil];
}

- (void)tearDown
{
    NSLog(@"%s", __PRETTY_FUNCTION__);
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
    self.oPGP = nil;
}

- (void)testLoadKeys {
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath], @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");

    let foundKeys1 = [self.oPGP getKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys1.count == 1);

    let foundKeys2 = [self.oPGP getKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
    XCTAssertTrue(foundKeys2.count == 0);

    let key = [self.oPGP findKeyForIdentifier:@"952E4E8B"];
    XCTAssertNotNil(key, @"Key 952E4E8B not found");
}

- (void) testSaveSecretKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);

    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];

    NSError *ssaveError = nil;
    XCTAssertTrue([self.oPGP exportKeysOfType:PGPKeySecret toFile:exportSecretKeyringPath error:&ssaveError]);
    XCTAssertNil(ssaveError);

    NSLog(@"Created file %@", exportSecretKeyringPath);

    // Check if can be load
    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
    XCTAssertNotNil([checkPGP importKeysFromFile:exportSecretKeyringPath]);
    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");

    let key = checkPGP.keys.anyObject;
    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertFalse(key.secretKey.isEncrypted, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void) testSavePublicKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);

    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];

    NSError *psaveError = nil;
    XCTAssertTrue([self.oPGP exportKeysOfType:PGPKeyPublic toFile:exportPublicKeyringPath error:&psaveError]);
    XCTAssertNil(psaveError);

    NSLog(@"Created file %@", exportPublicKeyringPath);
}


- (void) testPrimaryKey
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");

    let key = self.oPGP.keys.anyObject;

    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertFalse(key.secretKey.isEncrypted, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void) testSigning {
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    BOOL status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    let keyToSign = [self.oPGP findKeyForIdentifier:@"25A233C2952E4E8B"];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingKey:keyToSign passphrase:nil detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    let keyToValidateSign = [self.oPGP findKeyForIdentifier:@"25A233C2952E4E8B"];
    NSError *verifyError = nil;
    status = [self.oPGP verifyData:[NSData dataWithContentsOfFile:fileToSignPath] withSignature:signatureData usingKey:keyToValidateSign error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);

    // Signed data
    NSData *signedData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingKey:keyToSign passphrase:nil detached:NO error:&signatureError];
    XCTAssertNotNil(signedData);
    XCTAssertNil(signatureError);

    NSString *signedPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin.sig"];
    status = [signedData writeToFile:signedPath atomically:YES];
    XCTAssertTrue(status);

    // Verify
    status = [self.oPGP verifyData:signedData error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);
}

#define PLAINTEXT @"Plaintext: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse blandit justo eros.\n"

- (void) testEncryption
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);

    // Public key
    let keyToEncrypt = [self.oPGP findKeyForIdentifier:@"25A233C2952E4E8B"];
    
    XCTAssertNotNil(keyToEncrypt);

    NSData* plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.oPGP encryptData:plainData usingKey:keyToEncrypt armored:NO error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);
    
    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [self.oPGP decryptData:encryptedData passphrase:nil error:nil];
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");
    
    // ARMORED
    NSData *encryptedDataArmored = [self.oPGP encryptData:plainData usingKey:keyToEncrypt armored:YES error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedDataArmored);

    NSString *fileEncryptedArmored = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted.armored"];
    NSLog(@"%@",fileEncryptedArmored);
    status = [encryptedDataArmored writeToFile:fileEncryptedArmored atomically:YES];
    XCTAssertTrue(status);
}

- (void) testGPGEncryptedMessage
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *encryptedPath = [bundle pathForResource:@"secring-test-plaintext-encrypted-message" ofType:@"asc"];

    NSError *error = nil;
    [self.oPGP decryptData:[NSData dataWithContentsOfFile:encryptedPath] passphrase:nil error:&error];
}

- (void) testEcnryptWithMultipleRecipients
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
    
    // Public key
    let keyToEncrypt1 = [self.oPGP findKeyForIdentifier:@"952E4E8B"];
    let keyToEncrypt2 = [self.oPGP findKeyForIdentifier:@"66753341"];
    
    XCTAssertNotNil(keyToEncrypt1);
    XCTAssertNotNil(keyToEncrypt2);
    
    NSData* plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];
    
    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.oPGP encryptData:plainData usingPublicKeys:@[keyToEncrypt1.publicKey, keyToEncrypt2.publicKey] armored:NO error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);
    
    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.multiple.encrypted"];
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);
    
    // decrypt + validate decrypted message
    NSData *decryptedData = [self.oPGP decryptData:encryptedData passphrase:nil error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");
}
@end
