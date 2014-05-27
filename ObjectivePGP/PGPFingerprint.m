//
//  PGPFingerprint.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFingerprint.h"
#import "NSData+PGPUtils.h"

@implementation PGPFingerprint

- (instancetype) initWithData:(NSData *)keyData
{
    if (self = [self init]) {
        self.keyData = keyData;
        self.hashedData = [keyData pgpSHA1];
    }
    return self;
}

- (NSString *)description
{
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:self.hashedData.length * 2];
    const unsigned char *buf = self.hashedData.bytes;
    for (NSUInteger i = 0; i < self.hashedData.length; ++i) {
        [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }
    return [sbuf copy];
}

- (NSUInteger) hashLength
{
    return self.hashedData.length;
}

@end
