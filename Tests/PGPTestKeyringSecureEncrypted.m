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

@interface ObjectivePGPTestKeyringSecureEncrypted : XCTestCase
@property (nonatomic) NSString *workingDirectory;
@end

@implementation ObjectivePGPTestKeyringSecureEncrypted

- (void)setUp {
    [super setUp];
    NSString *newDir = [@"ObjectivePGPTests" stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *tmpDirectoryPath = [NSTemporaryDirectory() stringByAppendingPathComponent:newDir];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:tmpDirectoryPath]) {
        XCTFail(@"couldn't create tmpDirectoryPath");
    }
    self.workingDirectory = tmpDirectoryPath;
}

- (void)tearDown {
    [super tearDown];
    [[NSFileManager defaultManager] removeItemAtPath:self.workingDirectory error:nil];
}

- (void)testLoadKeyring {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];
    XCTAssertEqual(keyring.keys.count, (NSUInteger)1);
}

- (void)testUsers {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];

    let key = keyring.keys.firstObject;
    XCTAssert(key.secretKey.users.count == 1, @"Invalid users count");
}

- (void)testPrimaryKey {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];

    let key = keyring.keys.firstObject;
    XCTAssertTrue(key.isEncryptedWithPassword, @"Should be encrypted");
    XCTAssertEqualObjects([key.keyID longIdentifier], @"9528AAA17A9BC007", @"Invalid key identifier");
}

- (void)testKeyDecryption {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];
    let key = keyring.keys.firstObject;

    XCTAssertTrue(key.isEncryptedWithPassword);

    NSError *decryptError = nil;
    let decryptedKey = [key decryptedWithPassphrase:@"1234" error:&decryptError];
    XCTAssertNotEqualObjects(key, decryptedKey);
    XCTAssertNotNil(decryptedKey, @"Decryption failed");
    XCTAssertNil(decryptError, @"Decryption failed");
}

- (void)testDataDecryption {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"pubring-test-encrypted.gpg"]];

    let encKey = [keyring findKeyWithIdentifier:@"9528AAA17A9BC007"];
    // encrypt
    NSData *tmpdata = [@"this is test" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *encError;
    NSData *encData = [ObjectivePGP encrypt:tmpdata addSignature:NO usingKeys:@[encKey] passphraseForKey:nil error:&encError];
    XCTAssertNil(encError, @"Encryption failed");

    NSError *decError;
    NSData *decData = [ObjectivePGP decrypt:encData andVerifySignature:YES usingKeys:keyring.keys passphraseForKey:^NSString * _Nullable(PGPKey * _Nonnull key) { return @"1234"; } error:&decError];
    XCTAssertNotNil(decError, @"Decryption failed");
    XCTAssertNotNil(decData);
    XCTAssertEqualObjects(tmpdata, decData);
}

- (void)testEncryptedSignature {
    let keyring = [[PGPKeyring alloc] init];
    [keyring importKeys:[PGPTestUtils readKeysFromPath:@"secring-test-encrypted.gpg"]];
    BOOL status;

    // file to sign
    NSString *fileToSignPath = [self.workingDirectory stringByAppendingPathComponent:@"signed_file.bin"];
    status = [[@"12345678901234567890123456789" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:fileToSignPath atomically:YES];
    XCTAssertTrue(status);

    let keyToSign = [keyring findKeyWithIdentifier:@"9528AAA17A9BC007"];
    XCTAssertNotNil(keyToSign);

    // detached signature
    NSError *signatureError = nil;
    let data = [NSData dataWithContentsOfFile:fileToSignPath];
    let signatureData = [ObjectivePGP sign:data detached:YES usingKeys:@[keyToSign] passphraseForKey:^NSString * _Nullable(PGPKey *k) { return @"1234"; } error:&signatureError];
    XCTAssertNotNil(signatureData);
    XCTAssertNil(signatureError);

    NSString *signaturePath = [self.workingDirectory stringByAppendingPathComponent:@"signature.sig"];
    status = [signatureData writeToFile:signaturePath atomically:YES];
    XCTAssertTrue(status);
}

@end
