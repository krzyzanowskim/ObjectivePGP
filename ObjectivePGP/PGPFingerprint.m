//
//  PGPFingerprint.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 14/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFingerprint.h"
#import "NSData+PGPUtils.h"
#import "PGPFoundation.h"

@implementation PGPFingerprint

- (instancetype)initWithData:(NSData *)keyData {
    if (self = [self init]) {
        _keyData = keyData;
        _hashedData = [keyData pgp_SHA1];
    }
    return self;
}

- (NSString *)description {
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:self.hashedData.length * 2];
    const unsigned char *buf = self.hashedData.bytes;
    for (NSUInteger i = 0; i < self.hashedData.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return sbuf;
}

#pragma mark - isEqual

- (NSUInteger)hashLength {
    return self.hashedData.length;
}

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToFingerprintPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToFingerprintPacket:(PGPFingerprint *)packet {
    return PGPEqualObjects(self.hashedData,packet.hashedData) && PGPEqualObjects(self.keyData,packet.keyData);
}

- (NSUInteger)hash {
    NSUInteger result = 1;
    result = 31 * result + self.hashedData.hash;
    result = 31 * result + self.keyData.hash;
    return result;
}

@end
