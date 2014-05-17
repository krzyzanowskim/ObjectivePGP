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

@interface ObjectivePGPTestKeyringSecurePlaintext : XCTestCase
@property (strong) NSString *keyringPath;
@property (strong) ObjectivePGP *oPGP;
@end

@implementation ObjectivePGPTestKeyringSecurePlaintext

- (void)setUp
{
    [super setUp];
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.keyringPath = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown
{
    [super tearDown];
    self.oPGP = nil;
}

- (void)testLoadKeyring
{
    self.oPGP = [[ObjectivePGP alloc] init];
    BOOL status = [self.oPGP loadKeyring:self.keyringPath];
    XCTAssertTrue(status, @"Unable to load keyring");
    XCTAssert(self.oPGP.keys.count == 1, @"Should load 1 key");
}

- (void) testPrimaryKey
{
    [self.oPGP loadKeyring:self.keyringPath];

    for (PGPKey *key in self.oPGP.keys) {
        PGPSecretKeyPacket *secretKey = key.primaryKeyPacket;
        XCTAssert([key.primaryKeyPacket class] == [PGPSecretKeyPacket class],@"Key Should be PGPSecretKeyPacket");
        XCTAssertFalse(key.isEncrypted, @"Should not be encrypted");
        XCTAssertEqualObjects([secretKey.keyID longKeyString], @"25A233C2952E4E8B", @"Invalid key identifier");
    }
}

//- (void) testCRC24
//{
//    [self.oPGP loadKeyring:self.keyringPath];
//
//    /*
//     The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
//     four characters of radix-64 encoding by the same MIME base64
//     transformation, preceded by an equal sign (=).  The CRC is computed
//     by using the generator 0x864CFB and an initialization of 0xB704CE.
//     The accumulation is done on the data before it is converted to
//     radix-64, rather than on the converted data.  A sample implementation
//     of this algorithm is in the next section.
//     */
////    NSData *a = [@"sQBj" dataUsingEncoding:NSUTF8StringEncoding];
//    NSData *a = [[NSData alloc] initWithBase64EncodedString:@"sQBj" options:0];
//    NSString *sa = [a base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength];
//    NSLog(@"%@",sa);
//
//    for (PGPKey *key in self.oPGP.keys) {
//        PGPPacket *packet = key.primaryKeyPacket;
//        UInt32 crc24 = [packet crc24];
//        NSData *crc24Data = [NSData dataWithBytes:&crc24 length:sizeof(UInt32)];
//        NSString *base64 = [crc24Data base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength];
////        NSLog(@"%@",base64);
//    }
//}

@end
