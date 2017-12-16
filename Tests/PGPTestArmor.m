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

@interface ObjectivePGPTestArmor : XCTestCase
@property (nonatomic) NSString *workingDirectory;
@property (nonatomic) ObjectivePGP *pgp;
@end

@implementation ObjectivePGPTestArmor

- (void)setUp {
    [super setUp];
    self.pgp = [[ObjectivePGP alloc] init];

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
    self.pgp = nil;
}

- (void)testMultipleKeys {
    let keys = [PGPTestUtils readKeysFromFile:@"multiple-keys.asc"];
    [self.pgp.defaultKeyring importKeys:keys];
    XCTAssertEqual(keys.count, (NSUInteger)3);
    XCTAssertEqual(self.pgp.defaultKeyring.keys.count, (NSUInteger)3);
}

- (void)testArmorPublicKey {
    let keys = [PGPTestUtils readKeysFromFile:@"pubring-test-plaintext.gpg"];
    [self.pgp.defaultKeyring importKeys:keys];

    PGPKey *key = self.pgp.defaultKeyring.keys.firstObject;

    NSError *exportError = nil;
    NSData *keyData = [key.publicKey export:&exportError];
    XCTAssertNil(exportError);
    XCTAssertNotNil(keyData);

    var armoredString = [PGPArmor armored:keyData as:PGPArmorTypePublicKey];
    XCTAssertNotNil(armoredString);

    BOOL status = [[armoredString dataUsingEncoding:NSUTF8StringEncoding] writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"] atomically:YES];
    XCTAssertTrue(status);

    NSError *loadError = nil;
    armoredString = [NSString stringWithContentsOfFile:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"] encoding:NSASCIIStringEncoding error:&loadError];
    XCTAssertNil(loadError);
    XCTAssertNotNil(armoredString);

    NSError *readArmoredError = nil;
    NSData *decodedData = [PGPArmor readArmored:armoredString error:&readArmoredError];
    XCTAssertNil(readArmoredError);
    XCTAssertNotNil(decodedData);

    XCTAssertEqualObjects(decodedData, keyData);
}

//- (void) testEmbededArmoredData
//{
//    [self.pgp.defaultKeyring importKeysFromFile:self.pubKeyringPath];
//
//    PGPKey *key = self.pgp.keys[0];
//
//    NSError *exportError = nil;
//    NSData *keyData = [key export:&exportError];
//    XCTAssertNil(exportError);
//    XCTAssertNotNil(keyData);
//
//    NSData *armoredData = [PGPArmor armoredData:keyData as:PGPArmorTypePublicKey];
//    XCTAssertNotNil(armoredData);
//
//    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"]];
//    [fileHandle seekToEndOfFile];
//    [fileHandle writeData:[@"some buzzzzzzzz\n" dataUsingEncoding:NSUTF8StringEncoding]];
//    [fileHandle writeData:armoredData];
//    [fileHandle writeData:[@"\nmore buzzz\n" dataUsingEncoding:NSUTF8StringEncoding]];
//    [fileHandle closeFile];
//
//    NSError *loadError = nil;
//    NSString *armoredString = [NSString stringWithContentsOfFile:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"] encoding:NSASCIIStringEncoding error:&loadError];
//    XCTAssertNil(loadError);
//    XCTAssertNotNil(armoredString);
//
//    NSError *readArmoredError = nil;
//    NSData *decodedData = [PGPArmor readArmoredData:armoredString error:&readArmoredError];
//    XCTAssertNil(readArmoredError);
//    XCTAssertNotNil(decodedData);
//}

@end
