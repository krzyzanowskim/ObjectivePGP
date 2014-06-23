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
@property (strong) NSString *secKeyringPath;
@property (strong) NSString *pubKeyringPath;
@property (strong) NSString *workingDirectory;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSLog(@"%s", __PRETTY_FUNCTION__);

    self.oPGP = [[ObjectivePGP alloc] init];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.secKeyringPath = [bundle pathForResource:@"secring-test" ofType:@"gpg"];
    self.pubKeyringPath = [bundle pathForResource:@"pubring-test" ofType:@"gpg"];

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

//- (void)testLoadKeys
//{
//    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);
//
//    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath], @"Unable to load keyring");
//    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
//
//    NSArray *foundKeys = [self.oPGP getKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
//    XCTAssertNotNil(foundKeys, @"key not found");
//
//    foundKeys = [self.oPGP getKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
//    XCTAssertNil(foundKeys, @"found key, should not");
//
//    PGPKey *key = [self.oPGP getKeyForIdentifier:@"952E4E8B"];
//    XCTAssertNotNil(key, @"Key 952E4E8B not found");
//}
//
//- (void) testSaveSecretKeys
//{
//    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);
//
//    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
//
//    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
//
//    NSArray *secretKeys = [self.oPGP getKeysOfType:PGPKeySecret];
//    NSError *ssaveError = nil;
//    BOOL sstatus = [self.oPGP exportKeys:secretKeys toFile:exportSecretKeyringPath error:&ssaveError];
//    XCTAssertNil(ssaveError, @"");
//    XCTAssertTrue(sstatus, @"");
//
//    NSLog(@"Created file %@", exportSecretKeyringPath);
//
//    // Check if can be load
//    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
//    XCTAssertNotNil([checkPGP importKeysFromFile:exportSecretKeyringPath]);
//    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");
//
//    PGPKey *key = checkPGP.keys[0];
//    PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
//    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
//    XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
//    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
//}
//
//- (void) testSavePublicKeys
//{
//    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);
//
//    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);
//
//    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];
//
//    NSArray *publicKeys = [self.oPGP getKeysOfType:PGPKeyPublic];
//    NSError *psaveError = nil;
//    BOOL pstatus = [self.oPGP exportKeys:publicKeys toFile:exportPublicKeyringPath error:&psaveError];
//    XCTAssertNil(psaveError);
//    XCTAssertTrue(pstatus);
//
//    NSLog(@"Created file %@", exportPublicKeyringPath);
//}
//
//
//- (void) testPrimaryKey
//{
//    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);
//
//    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
//    XCTAssert(self.oPGP.keys.count > 0, @"Keys not loaded");
//
//    PGPKey *key = self.oPGP.keys[0];
//
//    PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
//    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
//    XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
//    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
//}
//
//- (void) testSigning
//{
//    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
//
//    // file to sign
//    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
//    BOOL status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
//    XCTAssertTrue(status);
//
//    PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B"];
//    XCTAssertNotNil(keyToSign);
//
//    // detached signature
//    NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign passphrase:nil detached:YES];
//    XCTAssertNotNil(signatureData);
//
//    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
//    status = [signatureData writeToFile:signaturePath atomically:YES];
//    XCTAssertTrue(status);
//
//    NSLog(@"Signature %@", signaturePath);
//
//    // Verify
//    PGPKey *keyToValidateSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B"];
//    status = [self.oPGP verifyData:[NSData dataWithContentsOfFile:fileToSignPath] withSignature:signatureData usingKey:keyToValidateSign];
//    XCTAssertTrue(status);
//
//    // Signed data
//    NSData *signedData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign passphrase:nil detached:NO];
//    XCTAssertNotNil(signedData);
//
//    NSString *signedPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin.sig"];
//    status = [signedData writeToFile:signedPath atomically:YES];
//    XCTAssertTrue(status);
//
//    NSLog(@"Signed file %@", signedPath);
//
//    // Verify
//    keyToValidateSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B"];
//    status = [self.oPGP verifyData:signedData];
//    XCTAssertTrue(status);
//}
//
#define PLAINTEXT @"Plaintext: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse blandit justo eros.\n"

- (void) testEncryption
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.pubKeyringPath]);
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);

    // Public key
    PGPKey *keyToEncrypt = [self.oPGP getKeyForIdentifier:@"28A83333F9C27197"];
    NSArray *secretKeys = [self.oPGP getKeysOfType:PGPKeySecret];
    PGPKey *keyToDecrypt = secretKeys[0];
    
    XCTAssertNotNil(keyToEncrypt);
    XCTAssertNotNil(keyToDecrypt);

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
    NSData *decryptedData = [self.oPGP decryptData:encryptedData usingSecretKey:keyToDecrypt passphrase:@"1234" error:nil];
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

@end
