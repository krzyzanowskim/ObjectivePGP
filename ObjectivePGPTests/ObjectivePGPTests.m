//
//  ObjectivePGPTests.m
//  ObjectivePGPTests
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <XCTest/XCTest.h>


//sec   2048R/AEEF64C8 2014-05-03
//uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
//ssb   2048R/7D4FCA45 2014-05-03

//pub   2048R/AEEF64C8 2014-05-03
//Key fingerprint = 816E 6A80 8067 D41E 4CB0  3FCC 9469 0093 AEEF 64C8
//uid                  Marcin Krzyzanowski (Test keys) <test+marcin.krzyzanowski@gmail.com>
//sub   2048R/7D4FCA45 2014-05-03

//pass ObjectivePGP


@interface ObjectivePGPTests : XCTestCase
@end

@implementation ObjectivePGPTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void) testDuplicates
{
}


@end
