//
//  ObjectivePGPTestKeyringSecureEncrypted.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ObjectivePGP.h"
#import "PGPSecretKeyPacket.h"

@interface ObjectivePGPTestKeyringSecureEncrypted : XCTestCase
@property (strong) NSString *secKeyringPath;
@property (strong) NSString *pubKeyringPath;
@property (strong) NSString *workingDirectory;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecureEncrypted

- (void)setUp
{
    [super setUp];
    NSLog(@"%s", __PRETTY_FUNCTION__);

    self.oPGP = [[ObjectivePGP alloc] init];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.secKeyringPath = [bundle pathForResource:@"secring-test-encrypted" ofType:@"gpg"];
    self.pubKeyringPath = [bundle pathForResource:@"pubring-test-encrypted" ofType:@"gpg"];

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

- (void)testLoadKeyring
{
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO]);
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
}

- (void) testUsers
{
    [self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO];

    PGPKey *key = self.oPGP.keys[0];
    XCTAssert(key.users.count == 1, @"Invalid users count");
}

- (void) testPrimaryKey
{
    [self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO];

    PGPKey *key = self.oPGP.keys[0];

    PGPSecretKeyPacket *secretKey = (PGPSecretKeyPacket *)key.primaryKeyPacket;
    XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
    XCTAssertTrue(key.isEncrypted, @"Should be encrypted");
    XCTAssertEqualObjects([secretKey.keyID longKeyString], @"9528AAA17A9BC007", @"Invalid key identifier");
}

- (void)testKeyDecryption
{
    [self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO];

    PGPKey *key = self.oPGP.keys[0];

    NSError *decryptError = nil;
    BOOL status = [key decrypt:@"1234" error:&decryptError];
    XCTAssertTrue(status, @"Decryption failed");
    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void)testDataDecryption
{
    [self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO];
    [self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO];
    
    
    PGPKey *encKey = [self.oPGP getKeyForIdentifier:@"9528AAA17A9BC007" type:PGPKeyPublic];
    // encrypt
    NSData *tmpdata = [@"this is test" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *encError;
    NSData *encData = [self.oPGP encryptData:tmpdata usingPublicKey:encKey armored:NO error:&encError];
    XCTAssertNil(encError, @"Encryption failed");

    NSError *decError;
    NSData *decData = [self.oPGP decryptData:encData passphrase:@"1234" error:&decError];
    XCTAssertNil(decError, @"Decryption failed");
    NSAssert([tmpdata isEqualToData:decData], @"Data should be equal");
    
//    PGPKey *key = self.oPGP.keys[0];
//    
//    NSError *decryptError = nil;
//    BOOL status = [key decrypt:@"1234" error:&decryptError];
//    XCTAssertTrue(status, @"Decryption failed");
//    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void) testEncryptedSignature
{
    BOOL status;

    [self.oPGP importKeysFromFile:self.secKeyringPath allowDuplicates:NO];

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"9528AAA17A9BC007" type:PGPKeySecret];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    NSData *signatureData = [self.oPGP signData:[NSData dataWithContentsOfFile:fileToSignPath] usingSecretKey:keyToSign passphrase:@"1234" detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);
}

@end
