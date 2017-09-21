//
//  PGPKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKey.h"
#import "PGPKey+Private.h"
#import "PGPPartialSubKey.h"
#import "PGPLogging.h"
#import "PGPMacros+Private.h"

#import "PGPSecretKeyPacket.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPSignatureSubpacket+Private.h"
#import "PGPRSA.h"
#import "PGPDSA.h"
#import "NSMutableData+PGPUtils.h"

#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPKey

- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey {
    if ((self = [super init])) {
        _secretKey = secretKey;
        _publicKey = publicKey;
    }
    return self;
}

- (BOOL)isSecret {
    return self.secretKey != nil;
}

- (BOOL)isPublic {
    return self.publicKey != nil;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, publicKey: %@, secretKey: %@", super.description, self.publicKey.keyID, self.secretKey.keyID];
}

- (nullable NSDate *)expirationDate {
    return self.publicKey.expirationDate ?: self.secretKey.expirationDate;
}

- (PGPKeyID *)keyID {
    return self.publicKey.keyID ?: self.secretKey.keyID;
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

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToKey:other];
    }
    return NO;
}

- (BOOL)isEqualToKey:(PGPKey *)other {
    return PGPEqualObjects(self.secretKey,other.secretKey) && PGPEqualObjects(self.publicKey,other.publicKey);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;

    result = prime * result + self.secretKey.hash;
    result = prime * result + self.publicKey.hash;

    return result;
}


#pragma mark - PGPExportable

/// Export public and secret keys together.
- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    let exportData = [NSMutableData data];
    if (self.publicKey) {
        [exportData pgp_appendData:[self export:PGPPartialKeyPublic error:error]];
    }

    if (self.secretKey) {
        [exportData pgp_appendData:[self export:PGPPartialKeySecret error:error]];
    }

    return exportData;
}

- (nullable NSData *)export:(PGPPartialKeyType)keyType error:(NSError *__autoreleasing _Nullable *)error {
    switch (keyType) {
        case PGPPartialKeyPublic: {
            if (!self.publicKey) {
                return nil;
            }

            return [self.publicKey export:error];
        }
        break;
        case PGPPartialKeySecret: {
            if (!self.secretKey) {
                return nil;
            }

            return [self.secretKey export:error];
        }
        break;
        default: {
            PGPLogError(@"Can't export unknown key type: %@", self);
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Can't export unknown key type"}];
            }
        }
        break;
    }

    return nil;
}

@end

NS_ASSUME_NONNULL_END
