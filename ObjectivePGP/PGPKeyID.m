//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
// Fingerprint:     4772 3A3C EE12 760F 7DC8  4AE0 1B63 BCB7 E810 38C6
// Long Key ID:                                    1B63 BCB7 E810 38C6 <- this
// Short Key ID:                                             E810 38C6

#import "PGPKeyID.h"
#import "PGPMacros.h"
#import "PGPFingerprint.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyID ()

@property (copy, nonatomic) NSData *longKey;

@end

@implementation PGPKeyID

- (nullable instancetype)initWithLongKey:(NSData *)longKeyData {
    if (longKeyData.length != 8) {
        return nil;
    }

    if (self = [super init]) {
        _longKey = [longKeyData copy];
    }
    return self;
}

- (instancetype)initWithFingerprint:(PGPFingerprint *)fingerprint {
    PGPAssertClass(fingerprint, PGPFingerprint);
    PGPAssertClass(fingerprint.hashedData, NSData);
    return ((self = [self initWithLongKey:[fingerprint.hashedData subdataWithRange:(NSRange){fingerprint.hashLength - 8, 8}]]));
}

- (NSString *)description {
    return [self longIdentifier];
}

- (NSData *)shortKey {
    return [self.longKey subdataWithRange:(NSRange){4, 4}];
}

- (NSString *)shortIdentifier {
    NSData *sKey = self.shortKey;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:sKey.length * 2];
    const unsigned char *buf = sKey.bytes;
    for (NSUInteger i = 0; i < sKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return sbuf;
}

- (NSString *)longIdentifier {
    NSData *lKey = self.longKey;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:lKey.length * 2];
    const unsigned char *buf = lKey.bytes;
    for (NSUInteger i = 0; i < lKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return sbuf;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToKeyID:other];
    }
    return NO;
}

- (BOOL)isEqualToKeyID:(PGPKeyID *)packet {
    return PGPEqualObjects(self.longKey, packet.longKey);
}

- (NSUInteger)hash {
    NSUInteger result = 1;
    result = 31 * result + self.longKey.hash;
    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    return PGPCast([[self.class allocWithZone:zone] initWithLongKey:self.longKey], PGPKeyID);
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing  _Nullable *)error {
    return self.longKey.copy;
}

@end

NS_ASSUME_NONNULL_END
