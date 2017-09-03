//
//  ObjectivePGPTestKeyringSecureEncrypted.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>
#import "PGPMacros+Private.h"
#import <XCTest/XCTest.h>

@interface ObjectivePGPTestKeyringSecureEncrypted : XCTestCase
@property (nonatomic) NSString *secKeyringPath;
@property (nonatomic) NSString *pubKeyringPath;
@property (nonatomic) NSString *workingDirectory;
@property (nonatomic) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecureEncrypted

- (void)setUp {
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

- (void)tearDown {
    NSLog(@"%s", __PRETTY_FUNCTION__);
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
    self.oPGP = nil;
}

- (void)testLoadKeyring {
    XCTAssertNotNil([self.oPGP importKeysFromFile:self.secKeyringPath]);
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
}

- (void)testUsers {
    [self.oPGP importKeysFromFile:self.secKeyringPath];

    let key = self.oPGP.keys.anyObject;
    XCTAssert(key.secretKey.users.count == 1, @"Invalid users count");
}

- (void)testPrimaryKey {
    [self.oPGP importKeysFromFile:self.secKeyringPath];

    let key = self.oPGP.keys.anyObject;

    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertTrue(key.secretKey.isEncrypted, @"Should be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longKeyString], @"9528AAA17A9BC007", @"Invalid key identifier");
}

- (void)testKeyDecryption {
    [self.oPGP importKeysFromFile:self.secKeyringPath];

    let key = self.oPGP.keys.anyObject;

    [self measureBlock:^{
        NSError *decryptError = nil;
        BOOL status = [key.secretKey decrypt:@"1234" error:&decryptError];
        XCTAssertTrue(status, @"Decryption failed");
        XCTAssertNil(decryptError, @"Decryption failed");
    }];
}

- (void)testDataDecryption {
    [self.oPGP importKeysFromFile:self.secKeyringPath];
    [self.oPGP importKeysFromFile:self.pubKeyringPath];

    let encKey = [self.oPGP findKeyForIdentifier:@"9528AAA17A9BC007"];
    // encrypt
    NSData *tmpdata = [@"this is test" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *encError;
    NSData *encData = [self.oPGP encryptData:tmpdata usingKeys:@[encKey] armored:NO error:&encError];
    XCTAssertNil(encError, @"Encryption failed");

    [self measureBlock:^{
        NSError *decError;
        NSData *decData = [self.oPGP decryptData:encData passphrase:@"1234" error:&decError];
        XCTAssertNil(decError, @"Decryption failed");
        XCTAssertNotNil(decData);
        XCTAssertEqualObjects(tmpdata, decData);
    }];
}

- (void)testEncryptedSignature {
    BOOL status;

    [self.oPGP importKeysFromFile:self.secKeyringPath];

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    let keyToSign = [self.oPGP findKeyForIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    let data = [NSData dataWithContentsOfFile:fileToSignPath];
    let signatureData = [self.oPGP signData:data usingKey:keyToSign passphrase:@"1234" detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);
}

@end
