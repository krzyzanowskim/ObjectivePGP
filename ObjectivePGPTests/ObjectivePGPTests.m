//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ObjectivePGP.h"


//sec   2048R/AEEF64C8 2014-05-03
//uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
//ssb   2048R/7D4FCA45 2014-05-03

//pub   2048R/AEEF64C8 2014-05-03
//Key fingerprint = 816E 6A80 8067 D41E 4CB0  3FCC 9469 0093 AEEF 64C8
//uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
//sub   2048R/7D4FCA45 2014-05-03

//pass ObjectivePGP


@interface ObjectivePGPTests : XCTestCase
@property (strong) ObjectivePGP *oPGP;
@property (strong) NSString *secringPathPlaintext, *secringPathEncrypted;
@property (strong) NSString *pubringPlaintext, *pubringEncrypted;
@end

@implementation ObjectivePGPTests

- (void)setUp
{
    [super setUp];

    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    self.secringPathPlaintext = [bundle pathForResource:@"secring-test-plaintext" ofType:@"gpg"];
    self.secringPathEncrypted = [bundle pathForResource:@"secring-test-encrypted" ofType:@"gpg"];
    self.pubringPlaintext = [bundle pathForResource:@"pubring-test-plaintext" ofType:@"gpg"];
    self.pubringEncrypted = [bundle pathForResource:@"pubring-test-encrypted" ofType:@"gpg"];

    self.oPGP = [[ObjectivePGP alloc] init];
}

- (void)tearDown
{
    [super tearDown];
    self.oPGP = nil;
}

- (void) testDuplicates
{
    [self.oPGP importKeysFromFile:self.pubringPlaintext allowDuplicates:YES];
    NSUInteger count1 = self.oPGP.keys.count;
    [self.oPGP importKeysFromFile:self.pubringPlaintext allowDuplicates:YES];
    NSUInteger count2 = self.oPGP.keys.count;
    
    NSAssert((count1 * 2) == count2, @"Loaded keys should be duplicated in count");
}

- (void) testNotDuplicates
{
    [self.oPGP importKeysFromFile:self.pubringPlaintext allowDuplicates:NO];
    NSUInteger count1 = self.oPGP.keys.count;
    [self.oPGP importKeysFromFile:self.pubringPlaintext allowDuplicates:NO];
    NSUInteger count2 = self.oPGP.keys.count;
    
    NSAssert(count1 == count2, @"Loaded keys should be equal");
}

//- (void) testNewOpenKeyring
//{
//    BOOL openedPubKeyringNewFormat    = [self.keyring open:self.pubringNewFormatPath];
//    XCTAssert(openedPubKeyringNewFormat, @"Unable to read file");
//}

//- (void) testOldOpenKeyring
//{
//    BOOL openedPubKeyringOldFormat    = [self.keyring open:self.pubringOldFormatPath];
//    XCTAssert(openedPubKeyringOldFormat, @"Unable to read file");
//}

- (void) testSecretKeyring
{
//    BOOL openedSecring    = [self.keyring open:self.secringPathPlaintext];
//    XCTAssert(openedSecring, @"Unable to read file");
}

//- (void)testExample
//{
//    XCTFail(@"No implementation for \"%s\"", __PRETTY_FUNCTION__);
//}

@end
