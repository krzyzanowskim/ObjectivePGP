//
//  PGPCompoundKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCompoundKey.h"
#import "PGPMacros.h"
#import "PGPLogging.h"
#import "PGPCompoundKey+Private.h"
#import "PGPSubKey.h"
#import "PGPSecretKeyPacket.h"

#import "PGPMacros.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPCompoundKey

- (instancetype)initWithSecretKey:(nullable PGPKey *)secretKey publicKey:(nullable PGPKey *)publicKey {
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
    let signingPacket = PGPCast(self.secretKey.signingKeyPacket,PGPSecretKeyPacket);
    if (!signingPacket) {
        PGPLogWarning(@"Need secret key to sign");
    }

    return signingPacket;
}

- (BOOL)isEqual:(id)object {
    if (object == self) {
        return YES;
    }

    let other = PGPCast(object, PGPCompoundKey);
    if (!other) {
        return NO;
    }

    return [self.secretKey isEqual:other.secretKey] && [self.publicKey isEqual:other.publicKey];
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + self.secretKey.hash;
    result = prime * result + self.publicKey.hash;
    return result;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing  _Nullable *)error {
    NSMutableData *exportData = [NSMutableData data];
    if (self.publicKey) {
        [exportData appendData:[self.publicKey export:error]];
    }
    
    if (self.secretKey) {
        [exportData appendData:[self.secretKey export:error]];
    }
    return exportData;
}

@end

NS_ASSUME_NONNULL_END
