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
    self.secKeyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.pubKeyringPath = [bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];

    NSString *newDir = [@"ObjectivePGPTests" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }
    self.workingDirectory = tmpDirectoryPath;
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

    BOOL status = [self.oPGP loadKeysFromKeyring:self.secKeyringPath];
    XCTAssertTrue(status, @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");

    NSArray *foundKeys = [self.oPGP getKeysForUserID:@"Marcin (test) <marcink@up-next.com>"];
    XCTAssertNotNil(foundKeys, @"key not found");

    foundKeys = [self.oPGP getKeysForUserID:@"ERR Marcin (test) <marcink@up-next.com>"];
    XCTAssertNil(foundKeys, @"found key, should not");

    PGPKey *key = [self.oPGP getKeyForIdentifier:@"952E4E8B"];
    XCTAssertNotNil(key, @"Key 952E4E8B not found");
}

- (void) testSaveSecretKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    BOOL status = [self.oPGP loadKeysFromKeyring:self.secKeyringPath];
    XCTAssertTrue(status, @"");

    NSString *exportSecretKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];

    NSArray *secretKeys = [self.oPGP getKeysOfType:PGPKeySecret];
    NSError *ssaveError = nil;
    BOOL sstatus = [self.oPGP saveKeys:secretKeys toKeyring:exportSecretKeyringPath error:&ssaveError];
    XCTAssertNil(ssaveError, @"");
    XCTAssertTrue(sstatus, @"");

    NSLog(@"Created file %@", exportSecretKeyringPath);

}

- (void) testSavePublicKeys
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    BOOL status = [self.oPGP loadKeysFromKeyring:self.pubKeyringPath];
    XCTAssertTrue(status);

    NSString *exportPublicKeyringPath = [self.workingDirectory stringByAppendingPathComponent:@"export-pubring-test-plaintext.gpg"];

    NSArray *publicKeys = [self.oPGP getKeysOfType:PGPKeyPublic];
    NSError *psaveError = nil;
    BOOL pstatus = [self.oPGP saveKeys:publicKeys toKeyring:exportPublicKeyringPath error:&psaveError];
    XCTAssertNil(psaveError);
    XCTAssertTrue(pstatus);

    NSLog(@"Created file %@", exportPublicKeyringPath);
}


- (void) testPrimaryKey
{
    NSLog(@"%s doing work...", __PRETTY_FUNCTION__);

    BOOL status = [self.oPGP loadKeysFromKeyring:self.secKeyringPath];
    XCTAssertTrue(status, @"");

    for (PGPKey *key in self.oPGP.keys) {
        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
    }
}

- (void) testDetachedSignature
{
    BOOL status = [self.oPGP loadKeysFromKeyring:self.secKeyringPath];
    XCTAssertTrue(status, @"");

    // copy keyring to verify
    [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[self.secKeyringPath lastPathComponent]] error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:self.pubKeyringPath toPath:[self.workingDirectory stringByAppendingPathComponent:[self.pubKeyringPath lastPathComponent]] error:nil];


    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B"];
    XCTAssertNotNil(keyToSign);

    NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign];
    XCTAssertNotNil(signatureData);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);

    NSLog(@"Signature %@", signaturePath);

    // Verify
    PGPKey *keyToValidateSign = [self.oPGP getKeyForIdentifier:@"25A233C2952E4E8B"];
    status = [self.oPGP verifyData:[NSData dataWithContentsOfFile:fileToSignPath] withSignature:signatureData usingKey:keyToValidateSign];
    XCTAssertTrue(status);

}

//- (void) testSignature
//{
//    BOOL loadStatus = [self.oPGP loadKeyring:self.keyringPath];
//    XCTAssertTrue(loadStatus, @"Keyring file should load properly");
//
//    NSString *newDir = [@"ObjectivePGPTests" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
//    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
//    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
//    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
//        XCTFail(@"couldn't create tmpDirectoryPath");
//    }
//
//    NSMutableData *keysData = [NSMutableData data];
//    for (PGPKey *key in self.oPGP.keys) {
//        NSError *error = nil;
//        NSData *keyData = [key export:&error];
//        XCTAssertNotNil(keyData, @"Can't export key");
//        [keysData appendData:keyData];
//
//        // Sign with key
//        PGPSignaturePacket *binarySign = [[PGPSignaturePacket alloc] init];
//        binarySign.type               = PGPSignatureBinaryDocument;
//        binarySign.publicKeyAlgorithm = PGPPublicKeyAlgorithmRSA;
//        binarySign.hashAlgoritm       = PGPHashSHA1;
//        NSData *signatureData = [binarySign signData:key data:[NSData dataWithContentsOfFile:self.keyringPath] userIDPacket:nil];
//        [signatureData writeToFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signature.sig"] atomically:YES];
//        [[NSData dataWithContentsOfFile:self.keyringPath] writeToFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signed_file.bin"] atomically:YES];
//
//        [[NSFileManager defaultManager] copyItemAtPath:self.keyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.keyringPath lastPathComponent]] error:nil];
//        [[NSFileManager defaultManager] copyItemAtPath:self.pubKeyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.pubKeyringPath lastPathComponent]] error:nil];
//    }
//    NSLog(@"%@",tmpDirectoryPath);
//    [[NSFileManager defaultManager] removeItemAtPath:tmpDirectoryPath error:nil];
//}

//- (void) testExport
//{
//    BOOL loadStatus = [self.oPGP loadKeysFromKeyring:self.keyringPath];
//    XCTAssertTrue(loadStatus, @"Keyring file should load properly");
//
//    NSString *newDir = [@"ObjectivePGPTests_" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
//    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
//    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
//    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
//        XCTFail(@"couldn't create tmpDirectoryPath");
//    }
//
//    NSMutableData *keysData = [NSMutableData data];
//    for (PGPKey *key in self.oPGP.keys) {
//        NSError *error = nil;
//        XCTAssert(key.users.count == 1, @"Users");
//
//        NSData *keyData = [key export:&error];
//        XCTAssertNotNil(keyData, @"Can't export key");
//        [keysData appendData:keyData];
//
//        // Sign with key
//        if (key.type == PGPKeySecret) {
//            NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:self.keyringPath] usingSecretKey:key];
//            XCTAssertNotNil(signatureData, @"Signature can't be nil");
//            [signatureData writeToFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signature.sig"] atomically:YES];
//
//            [[NSFileManager defaultManager] copyItemAtPath:self.keyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:@"signed_file.bin"] error:nil];
//            [[NSFileManager defaultManager] copyItemAtPath:self.keyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.keyringPath lastPathComponent]] error:nil];
//            [[NSFileManager defaultManager] copyItemAtPath:self.pubKeyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.pubKeyringPath lastPathComponent]] error:nil];
//
//            // verify
//            BOOL verified = [self.oPGP verifyData:[[NSData alloc] initWithContentsOfFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signed_file.bin"]]
//                        withSignature:[[NSData alloc] initWithContentsOfFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signature.sig"]]
//                        usingPublicKey:key];
//
//            XCTAssertTrue(verified, @"signature not verified");
//        }
//
//    }
//
//    NSString *exportKeyringPath = [tmpDirectoryPath stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
//    //[keysData writeToFile:exportKeyringPath atomically:YES];
//    [self.oPGP saveKeys:self.oPGP.keys toKeyring:exportKeyringPath error:nil];
//    NSLog(@"exported key to %@",exportKeyringPath);
//
//    // Check load
//    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
//    loadStatus = [checkPGP loadKeysFromKeyring:exportKeyringPath];
//    XCTAssertTrue(loadStatus, @"Exported file should load properly");
//
//    for (PGPKey *key in checkPGP.keys) {
//        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
//        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
//        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
//        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
//    }
//
//    [[NSFileManager defaultManager] removeItemAtPath:tmpDirectoryPath error:nil];
//}

@end
