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

- (void)testLoadKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO], @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");

    NSArray *foundKeys = [self.oPGP getKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
    XCTAssertNotNil(foundKeys, @"key not found");

    foundKeys = [self.oPGP getKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
    XCTAssertNil(foundKeys, @"found key, should not");

    PGPKey *key = [self.oPGP getKeyForIdentifier:@"952E4E8B" type:PGPKeySecret];
    XCTAssertNotNil(key, @"Key 952E4E8B not found");
}

- (void) testSaveSecretKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);

    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];

    NSArray *secretKeys = [self.oPGP getKeysOfType:PGPKeySecret];
    NSError *ssaveError = nil;
    BOOL sstatus = [self.oPGP exportKeys:secretKeys toFile:exportSecretKeyringPath error:&ssaveError];
    XCTAssertNil(ssaveError, @"");
    XCTAssertTrue(sstatus, @"");

    NSLog(@"Created file %@", exportSecretKeyringPath);

    // Check if can be load
    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
    XCTAssertNotNil([checkPGP importKeysFromFile:exportSecretKeyringPath allowDuplicates:NO]);
    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");

    PGPKey *key = checkPGP.keys[0];
    PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
    XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void) testSavePublicKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO]);

    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];

    NSArray *publicKeys = [self.oPGP getKeysOfType:PGPKeyPublic];
    NSError *psaveError = nil;
    BOOL pstatus = [self.oPGP exportKeys:publicKeys toFile:exportPublicKeyringPath error:&psaveError];
    XCTAssertNil(psaveError);
    XCTAssertTrue(pstatus);

    NSLog(@"Created file %@", exportPublicKeyringPath);
}


- (void) testPrimaryKey
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);
    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");

    PGPKey *key = self.oPGP.keys[0];

    PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
    XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
}

- (void) testSigning
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    BOOL status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B" type:PGPKeySecret];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign passphrase:nil detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);

    NSLog(@"Signature %@", signaturePath);

    // Verify
    PGPKey *keyToValidateSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B" type:PGPKeySecret];
    NSError *verifyError = nil;
    status = [self.oPGP verifyData:[NSData dataWithContentsOfFile:fileToSignPath] withSignature:signatureData usingKey:keyToValidateSign error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);

    // Signed data
    NSData *signedData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign passphrase:nil detached:NO error:&signatureError];
    XCTAssertNotNil(signedData);
    XCTAssertNil(signatureError);

    NSString *signedPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin.sig"];
    status = [signedData writeToFile:signedPath atomically:YES];
    XCTAssertTrue(status);

    NSLog(@"Signed file %@", signedPath);

    // Verify
    keyToValidateSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B" type:PGPKeySecret];
    status = [self.oPGP verifyData:signedData error:&verifyError];
    XCTAssertTrue(status);
    XCTAssertNil(verifyError);
}

#define PLAINTEXT @"Plaintext: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse blandit justo eros.\n"

- (void) testEncryption
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);

    // Public key
    PGPKey *keyToEncrypt = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B" type:PGPKeyPublic];
    
    XCTAssertNotNil(keyToEncrypt);

    NSData* plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];

    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.oPGP encryptData:plainData usingPublicKey:keyToEncrypt armored:NO error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedData);
    
    // file encrypted
    NSString *fileEncrypted = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted"];
    NSLog(@"%@",fileEncrypted);
    BOOL status = [encryptedData writeToFile:fileEncrypted atomically:YES];
    XCTAssertTrue(status);

    // decrypt + validate decrypted message
    NSData *decryptedData = [self.oPGP decryptData:encryptedData passphrase:nil error:nil];
    XCTAssertNotNil(decryptedData);
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
    XCTAssertNotNil(decryptedString);
    XCTAssertEqualObjects(decryptedString, PLAINTEXT, @"Decrypted data mismatch");
    
    // ARMORED
    NSData *encryptedDataArmored = [self.oPGP encryptData:plainData usingPublicKey:keyToEncrypt armored:YES error:&encryptError];
    XCTAssertNil(encryptError);
    XCTAssertNotNil(encryptedDataArmored);

    NSString *fileEncryptedArmored = [self.workingDirectory stringByAppendingPathComponent:@"plaintext.encrypted.armored"];
    NSLog(@"%@",fileEncryptedArmored);
    status = [encryptedDataArmored writeToFile:fileEncryptedArmored atomically:YES];
    XCTAssertTrue(status);
}

- (void) testGPGEncryptedMessage
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *encryptedPath = [bundle pathForResource:@"secring-test-plaintext-encrypted-message" ofType:@"asc"];

    NSError *error = nil;
    [self.oPGP decryptData:[NSData dataWithContentsOfFile:encryptedPath] passphrase:nil error:&error];
}

- (void) testEcnryptWithMultipleRecipients
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);
    
    // Public key
    PGPKey *keyToEncrypt1 = [self.oPGP getKeyForIdentifier:@"952E4E8B" type:PGPKeyPublic];
    PGPKey *keyToEncrypt2 = [self.oPGP getKeyForIdentifier:@"66753341" type:PGPKeyPublic];
    
    XCTAssertNotNil(keyToEncrypt1);
    XCTAssertNotNil(keyToEncrypt2);
    
    NSData* plainData = [PLAINTEXT dataUsingEncoding:NSUTF8StringEncoding];
    [plainData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"plaintext.txt"] atomically:YES];
    
    // encrypt PLAINTEXT
    NSError *encryptError = nil;
    NSData *encryptedData = [self.oPGP encryptData:plainData usingPublicKeys:@[keyToEncrypt1, keyToEncrypt2] armored:NO error:&encryptError];
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
