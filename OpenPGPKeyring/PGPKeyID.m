//
//  PGPKeyID.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
// Fingerprint:     4772 3A3C EE12 760F 7DC8  4AE0 1B63 BCB7 E810 38C6
// Long Key ID:                                    1B63 BCB7 E810 38C6 <- this
// Short Key ID:                                             E810 38C6

#import "PGPKeyID.h"

@implementation PGPKeyID

- (instancetype) initWithLongKey:(NSData *)longKeyData
{
    if (longKeyData.length != 8) {
        return nil;
    }

    if (self = [self init]) {
        _longKey = longKeyData;
    }
    return self;
}

- (NSData *)shortKey
{
    return [self.longKey subdataWithRange:(NSRange){4,4}];
}

- (NSString *)shortKeyString
{
    NSData *sKey = self.shortKey;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:sKey.length * 2];
    const unsigned char *buf = sKey.bytes;
    for (NSUInteger i = 0; i < sKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }
    return [sbuf copy];
}

- (NSString *)longKeyString
{
    NSData *lKey = self.longKey;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:lKey.length * 2];
    const unsigned char *buf = lKey.bytes;
    for (NSUInteger i = 0; i < lKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (NSUInteger)buf[i]];
    }
    return [sbuf copy];
}

@end
