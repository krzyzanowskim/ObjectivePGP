//
//  PGPKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKey.h"
#import "PGPKey+Private.h"
#import "PGPLogging.h"
#import "PGPMacros.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSubKey.h"

#import "PGPMacros.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPKey

- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey {
    if ((self = [super init])) {
        _secretKey = secretKey;
        _publicKey = publicKey;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, publicKey: %@, secretKey: %@", super.description, self.publicKey.keyID, self.secretKey.keyID];
}

- (nullable PGPSecretKeyPacket *)signingSecretKey {
    if (!self.secretKey) {
        PGPLogDebug(@"Need secret key to sign");
        return nil;
    }

    // find secret key based on the public key signature (unless self signed secret key)
    let signingPacket = PGPCast(self.secretKey.signingKeyPacket, PGPSecretKeyPacket);
    if (!signingPacket) {
        PGPLogWarning(@"Need secret key to sign");
    }

    return signingPacket;
}

- (BOOL)isEqual:(id)object {
    if (object == self) {
        return YES;
    }

    let other = PGPCast(object, PGPKey);
    if (!other) {
        return NO;
    }

    BOOL result = YES;
    if (self.secretKey) {
        result = [self.secretKey isEqual:other.secretKey];
    }

    if (result && self.publicKey) {
        result = [self.publicKey isEqual:other.publicKey];
    }

    return result;
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 7;
    result = prime * result + self.secretKey.hash;
    result = prime * result + self.publicKey.hash;
    return result;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    NSMutableData *exportData = [NSMutableData data];
    if (self.publicKey) {
        let exported = [self.publicKey export:error];
        if (exported) {
            [exportData appendData:exported];
        }
    }

    if (self.secretKey) {
        let exported = [self.secretKey export:error];
        if (exported) {
            [exportData appendData:exported];
        }
    }
    return exportData;
}

@end

NS_ASSUME_NONNULL_END
