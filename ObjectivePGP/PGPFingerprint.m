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
        self.hashData = [keyData pgpSHA1];
    }
    return self;
}

- (NSString *)description
{
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:self.hashData.length * 2];
    const unsigned char *buf = self.hashData.bytes;
    for (NSUInteger i = 0; i < self.hashData.length; ++i) {
        [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }
    return [sbuf copy];
}

- (NSUInteger) hashLength
{
    return self.hashData.length;
}

@end
