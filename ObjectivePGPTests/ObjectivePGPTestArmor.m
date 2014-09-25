//
//  ObjectivePGPTestArmor.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ObjectivePGP.h"
#import "PGPSecretKeyPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPArmor.h"


@interface ObjectivePGPTestArmor : XCTestCase
@property (strong) NSString *secKeyringPath;
@property (strong) NSString *pubKeyringPath;
@property (strong) NSString *workingDirectory;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestArmor

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


- (void) testArmorPublicKey
{
    [self.oPGP importKeysFromFile:self.pubKeyringPath allowDuplicates:NO];

    PGPKey *key = self.oPGP.keys[0];

    NSError *exportError = nil;
    NSData *keyData = [key export:&exportError];
    XCTAssertNil(exportError);
    XCTAssertNotNil(keyData);

    NSData *armoredData = [PGPArmor armoredData:keyData as:PGPArmorTypePublicKey];
    XCTAssertNotNil(armoredData);

    BOOL status = [armoredData writeToFile:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"] atomically:YES];
    XCTAssertTrue(status);

    NSError *loadError = nil;
    NSString *armoredString = [NSString stringWithContentsOfFile:[self.workingDirectory stringByAppendingPathComponent:@"pubkey.asc"] encoding:NSASCIIStringEncoding error:&loadError];
    XCTAssertNil(loadError);
    XCTAssertNotNil(armoredString);

    NSError *readArmoredError = nil;
    NSData *decodedData = [PGPArmor readArmoredData:armoredString error:&readArmoredError];
    XCTAssertNil(readArmoredError);
    XCTAssertNotNil(decodedData);

    XCTAssertEqualObjects(decodedData, keyData);
}

//- (void) testEmbededArmoredData
//{
//    [self.oPGP importKeysFromFile:self.pubKeyringPath];
//
//    PGPKey *key = self.oPGP.keys[0];
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
