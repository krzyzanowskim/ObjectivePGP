//
//  PGPKeyID.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
// Fingerprint:     4772 3A3C EE12 760F 7DC8  4AE0 1B63 BCB7 E810 38C6
// Long Key ID:                                    1B63 BCB7 E810 38C6 <- this
// Short Key ID:                                             E810 38C6

#import "PGPKeyID.h"

@implementation PGPKeyID

- (instancetype) initWithFingerprint:(PGPFingerprint *)fingerprint
{
    if (!fingerprint)
        return nil;

    if (self = [self initWithLongKey:[fingerprint.hashedData subdataWithRange:(NSRange){fingerprint.hashLength - 8,8}]]) {
        
    }

    return self;
}

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

- (NSString *)description
{
    return [self longKeyString];
}

- (NSData *)exportKeyData
{
    return [_longKey copy];
}

- (BOOL)isEqual:(id)object
{
    if (self == object) {
        return YES;
    }

    if ([self class] != [object class]) {
        return NO;
    }

    PGPKeyID *other = object;
    return [self.longKey isEqualToData:other.longKey];
}

- (BOOL) isEqualToKeyID:(PGPKeyID *)keyID
{
    return [self isEqual:keyID];
}

- (NSUInteger)hash
{
    const NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + [_longKey hash];
    return result;
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
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return [sbuf copy];
}

- (NSString *)longKeyString
{
    NSData *lKey = self.longKey;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:lKey.length * 2];
    const unsigned char *buf = lKey.bytes;
    for (NSUInteger i = 0; i < lKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return [sbuf copy];
}

@end
