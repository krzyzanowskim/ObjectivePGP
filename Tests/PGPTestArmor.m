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
    let keyring = [[PGPKeyring alloc] init];
    let keys = [PGPTestUtils readKeysFromPath:@"multiple-keys.asc"];
    [keyring importKeys:keys];
    XCTAssertEqual(keys.count, (NSUInteger)3);
    XCTAssertEqual(keyring.keys.count, (NSUInteger)3);
}

- (void)testArmorPublicKey {
    let keyring = [[PGPKeyring alloc] init];
    let keys = [PGPTestUtils readKeysFromPath:@"pubring-test-plaintext.gpg"];
    [keyring importKeys:keys];

    PGPKey *key = keyring.keys.firstObject;

    NSError *exportError = nil;
    NSData *keyData = [key.publicKey export:&exportError];
    XCTAssertNil(exportError);
    XCTAssertNotNil(keyData);

    var armoredString = [PGPArmor armored:keyData as:PGPArmorPublicKey];
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

- (void)testLargeArmour {
    NSError *loadError = nil;
    let path = [PGPTestUtils pathToBundledFile:@"largeArmoredMessage.txt"];
    NSString * armoredString = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:&loadError];
    
    NSData * armoredData = [NSData dataWithContentsOfFile:path options:NSDataReadingMapped error:&loadError];
    XCTAssertNil(loadError);
    XCTAssertNotNil(armoredString);

    NSError *readArmoredError = nil;
    NSDate * start = [NSDate now];
    NSData *decodedData = [PGPArmor readArmored:armoredString error:&readArmoredError];
    NSLog(@"old method took %0.04f",-start.timeIntervalSinceNow);
    start = [NSDate now];
    NSData *decodedData2 = [PGPArmor readArmoredData:armoredData error:&readArmoredError];
    NSLog(@"new method took %0.04f",-start.timeIntervalSinceNow);
  
    XCTAssertNil(readArmoredError);
    XCTAssertNotNil(decodedData);

    XCTAssertEqualObjects(decodedData, decodedData2);
}

-(void)testConvertArmoredMessage2BinaryBlocks{
    NSError *loadError = nil;
    let path = [PGPTestUtils pathToBundledFile:@"largeArmoredMessage.txt"];

    NSData * armoredData = [NSData dataWithContentsOfFile:path options:NSDataReadingMapped error:&loadError];
    NSDate * start = [NSDate now];
    NSError * error = nil;
    let binRingDataOld = [PGPArmor convertArmoredMessage2BinaryBlocksWhenNecessary:armoredData error:&error];
    XCTAssertNil(error);
     NSLog(@"old method took %0.04f",-start.timeIntervalSinceNow);
    start = [NSDate now];

    let binRingDataNew = [PGPArmor convertArmoredData2BinaryBlocksWhenNecessary:armoredData error:&error];
     NSLog(@"new method took %0.04f",-start.timeIntervalSinceNow);
    
    XCTAssertNil(error);
    XCTAssertNotNil(binRingDataNew);

    XCTAssertEqualObjects(binRingDataOld, binRingDataNew);
    
}

-(void)testReadKeysFromArmoredData{
    NSError *loadError = nil;
    let path = [PGPTestUtils pathToBundledFile:@"issue62-keys.asc"];

    NSData * armoredData = [NSData dataWithContentsOfFile:path options:NSDataReadingMapped error:&loadError];
    NSDate * start = [NSDate now];
    NSError * error = nil;
    let keys1 = [ObjectivePGP readKeysFromData:armoredData error:&error];
    
    NSThread.currentThread.threadDictionary[@"USE_PGP_DATA_SCANNER"] = @YES;
    let keys2 = [ObjectivePGP readKeysFromData:armoredData error:&error];
    NSThread.currentThread.threadDictionary[@"USE_PGP_DATA_SCANNER"] = nil;
    XCTAssertEqualObjects(keys1, keys2);
    
}
-(void)testConvertMultipleArmoredMessage2BinaryBlocks{
    NSError *loadError = nil;
    let path = [PGPTestUtils pathToBundledFile:@"issue62-keys.asc"];

    NSData * armoredData = [NSData dataWithContentsOfFile:path options:NSDataReadingMapped error:&loadError];
    NSDate * start = [NSDate now];
    NSError * error = nil;
    let binRingDataOld = [PGPArmor convertArmoredMessage2BinaryBlocksWhenNecessary:armoredData error:&error];
    XCTAssertNil(error);
     NSLog(@"old method took %0.04f",-start.timeIntervalSinceNow);
    start = [NSDate now];

    let binRingDataNew = [PGPArmor convertArmoredData2BinaryBlocksWhenNecessary:armoredData error:&error];
     NSLog(@"new method took %0.04f",-start.timeIntervalSinceNow);
    
    
    
    XCTAssertNil(error);
    XCTAssertNotNil(binRingDataNew);

    XCTAssertEqualObjects(binRingDataOld, binRingDataNew);
    
}


//- (void) testEmbededArmoredData
//{
//    [keyring importKeysfromPath:self.pubKeyringPath];
//
//    PGPKey *key = self.pgp.keys[0];
//
//    NSError *exportError = nil;
//    NSData *keyData = [key export:&exportError];
//    XCTAssertNil(exportError);
//    XCTAssertNotNil(keyData);
//
//    NSData *armoredData = [PGPArmor armoredData:keyData as:PGPArmorPublicKey];
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
