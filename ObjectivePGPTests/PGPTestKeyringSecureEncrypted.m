//
//  ObjectivePGPTestKeyringSecureEncrypted.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>
#import "PGPMacros+Private.h"
#import "PGPTestUtils.h"
#import <XCTest/XCTest.h>

@interface ObjectivePGPTestKeyringSecureEncrypted : XCTestCase
@property (nonatomic) NSString *secKeyringPath;
@property (nonatomic) NSString *pubKeyringPath;
@property (nonatomic) NSString *workingDirectory;
@property (nonatomic) ObjectivePGP *pgp;
@end

@implementation ObjectivePGPTestKeyringSecureEncrypted

- (void)setUp {
    [super setUp];
    NSLog(@"%s", __PRETTY_FUNCTION__);

    self.pgp = [[ObjectivePGP alloc] init];

    let bundle = PGPTestUtils.filesBundle;
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

- (void)importSecureKeyring {
    let keys = [self.pgp keysFromFile:self.secKeyringPath];
    [self.pgp importKeys:keys];
}

- (void)importPublicKeyring {
    let keys = [self.pgp keysFromFile:self.pubKeyringPath];
    [self.pgp importKeys:keys];
}

- (void)tearDown {
    NSLog(@"%s", __PRETTY_FUNCTION__);
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
    self.pgp = nil;
}

- (void)testLoadKeyring {
    let keys = [self.pgp keysFromFile:self.secKeyringPath];
    [self.pgp importKeys:keys];
    XCTAssert(self.pgp.keys.count == 1, @"Should load 1 key");
}

- (void)testUsers {
    [self importSecureKeyring];

    let key = self.pgp.keys.firstObject;
    XCTAssert(key.secretKey.users.count == 1, @"Invalid users count");
}

- (void)testPrimaryKey {
    [self importSecureKeyring];

    let key = self.pgp.keys.firstObject;

    let secretKeyPacket = PGPCast(key.secretKey.primaryKeyPacket, PGPSecretKeyPacket);
    XCTAssertTrue(key.secretKey.isEncryptedWithPassword, @"Should be encrypted");
    XCTAssertEqualObjects([secretKeyPacket.keyID longIdentifier], @"9528AAA17A9BC007", @"Invalid key identifier");
}

- (void)testKeyDecryption {
    [self importSecureKeyring];
    let key = self.pgp.keys.firstObject;

    XCTAssertTrue(key.isEncryptedWithPassword);

    NSError *decryptError = nil;
    let decryptedKey = [key decryptedWithPassphrase:@"1234" error:&decryptError];
    XCTAssertNotEqualObjects(key, decryptedKey);
    XCTAssertNotNil(decryptedKey, @"Decryption failed");
    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void)testDataDecryption {
    [self importSecureKeyring];
    [self importPublicKeyring];

    let encKey = [self.pgp findKeyWithIdentifier:@"9528AAA17A9BC007"];
    // encrypt
    NSData *tmpdata = [@"this is test" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *encError;
    NSData *encData = [self.pgp encrypt:tmpdata usingKeys:@[encKey] armored:NO error:&encError];
    XCTAssertNil(encError, @"Encryption failed");

    NSError *decError;
    NSData *decData = [self.pgp decrypt:encData passphrase:@"1234" error:&decError];
    XCTAssertNil(decError, @"Decryption failed");
    XCTAssertNotNil(decData);
    XCTAssertEqualObjects(tmpdata, decData);
}

- (void)testEncryptedSignature {
    [self importSecureKeyring];
    BOOL status;

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    status = [[NSFileManager defaultManager] copyItemAtPath:self.secKeyringPath toPath:fileToSignPath error:nil];
    XCTAssertTrue(status);

    let keyToSign = [self.pgp findKeyWithIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    let data = [NSData dataWithContentsOfFile:fileToSignPath];
    let signatureData = [self.pgp sign:data usingKey:keyToSign passphrase:@"1234" detached:YES error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);
}

@end
