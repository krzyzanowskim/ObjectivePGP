//
//  PGPFingerprint.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFingerprint.h"

@implementation PGPFingerprint

- (instancetype) initWithData:(NSData *)data
{
    if (self = [self init]) {
        self.data = data;
    }
    return self;
}

- (NSString *)description
{
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:self.data.length * 2];
    const unsigned char *buf = self.data.bytes;
    for (NSUInteger i = 0; i < self.data.length; ++i) {
        [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }
    return [sbuf copy];
}

- (NSUInteger) length
{
    return self.data.length;
}

@end
