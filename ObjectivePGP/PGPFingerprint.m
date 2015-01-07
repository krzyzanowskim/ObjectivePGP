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
        _keyData = keyData;
        _hashedData = [keyData pgp_SHA1];
    }
    return self;
}

- (NSString *)description
{
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:self.hashedData.length * 2];
    const unsigned char *buf = self.hashedData.bytes;
    for (NSUInteger i = 0; i < self.hashedData.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return [sbuf copy];
}

- (NSUInteger) hashLength
{
    return self.hashedData.length;
}

- (NSUInteger)hash
{
    const NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + [_hashedData hash];
    result = prime * result + [_keyData hash];
    return result;
}

- (BOOL)isEqual:(id)object
{
    if (self == object) {
        return YES;
    }
    
    if ([self class] != [object class]) {
        return NO;
    }
    
    PGPFingerprint *other = object;
    return [self.keyData isEqualToData:other.keyData] && [self.hashedData isEqualToData:other.hashedData];
}

- (BOOL) isEqualToFingerprint:(PGPFingerprint *)fingerprint
{
    return [self isEqual:fingerprint];
}

@end
