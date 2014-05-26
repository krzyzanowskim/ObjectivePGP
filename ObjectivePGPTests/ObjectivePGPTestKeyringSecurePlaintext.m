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
@property (strong) NSString *keyringPath;
@property (strong) NSString *pubKeyringPath;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.keyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.pubKeyringPath = [bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown
{
    [super tearDown];
    self.oPGP = nil;
}

//- (void)testLoadKeyring
//{
//    self.oPGP = [[ObjectivePGP alloc] init];
//    BOOL status = [self.oPGP loadKeyring:self.keyringPath];
//    XCTAssertTrue(status, @"Unable to load keyring");
//    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
//}
//
//- (void) testPrimaryKey
//{
//    [self.oPGP loadKeyring:self.keyringPath];
//
//    for (PGPKey *key in self.oPGP.keys) {
//        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
//        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
//        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
//        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
//    }
//}

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

- (void) testExport
{
    BOOL loadStatus = [self.oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(loadStatus, @"Keyring file should load properly");

    NSString *newDir = [@"ObjectivePGPTests_" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }

    NSMutableData *keysData = [NSMutableData data];
    for (PGPKey *key in self.oPGP.keys) {
        NSError *error = nil;
        XCTAssert(key.users.count == 1, @"Users");

        NSData *keyData = [key export:&error];
        XCTAssertNotNil(keyData, @"Can't export key");
        [keysData appendData:keyData];

        // Sign with key
        if (key.type == PGPKeySecret) {
            NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:self.keyringPath] withSecretKey:key];
            [signatureData writeToFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signature.sig"] atomically:YES];

            [[NSFileManager defaultManager] copyItemAtPath:self.keyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:@"signed_file.bin"] error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:self.keyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.keyringPath lastPathComponent]] error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:self.pubKeyringPath toPath:[tmpDirectoryPath stringByAppendingPathComponent:[self.pubKeyringPath lastPathComponent]] error:nil];

            // verify
            [self.oPGP verifyData:[[NSData alloc] initWithContentsOfFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signed_file.bin"]]
                        signature:[[NSData alloc] initWithContentsOfFile:[tmpDirectoryPath stringByAppendingPathComponent:@"signature.sig"]]
                        publicKey:key];
        }

    }

    NSString *exportKeyringPath = [tmpDirectoryPath stringByAppendingPathComponent:@"export-secring-test-plaintext.gpg"];
    [keysData writeToFile:exportKeyringPath atomically:YES];
    NSLog(@"exported key to %@",exportKeyringPath);

    // Check load
    ObjectivePGP *checkPGP = [[ObjectivePGP alloc] init];
    loadStatus = [checkPGP loadKeyring:exportKeyringPath];
    XCTAssertTrue(loadStatus, @"Exported file should load properly");

    for (PGPKey *key in checkPGP.keys) {
        PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
    }

    [[NSFileManager defaultManager] removeItemAtPath:tmpDirectoryPath error:nil];
}

@end
