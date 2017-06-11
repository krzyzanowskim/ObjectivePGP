//
//  PGPCompoundKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCompoundKey.h"
#import "PGPSubKey.h"
#import "PGPSecretKeyPacket.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPCompoundKey

- (instancetype)initWithSecretKey:(nullable PGPKey *)secretKey publicKey:(nullable PGPKey *)publicKey {
    if ((self = [super init])) {
        _secretKey = secretKey;
        _publicKey = publicKey;
    }
    return self;
}

- (nullable PGPSecretKeyPacket *)signingSecretKey {
    if (!self.secretKey) {
        PGPLogDebug(@"Need secret key to sign");
        return nil;
    }

    // find secret key based on the public key signature (unless self signed secret key)
    if (self.secretKey.signingKeyPacket) {
        return PGPCast(self.secretKey.signingKeyPacket, PGPSecretKeyPacket);
    }

    for (PGPSubKey *subKey in self.publicKey.subKeys) {
        let signaturePacket = subKey.bindingSignature;
        if (signaturePacket && signaturePacket.canBeUsedToSign) {
            let keyIdx = [self.secretKey.subKeys indexOfObject:subKey];
            if (keyIdx == NSNotFound) {
                continue;
            }

            PGPSubKey *secretSubKey = self.secretKey.subKeys[keyIdx];
            if (!secretSubKey) {
                continue;
            }


            // get the corresponding secret key packet
            // subKey.primaryKeyPacket;
        }
    }

    PGPLogDebug(@"Need secret key to sign");
    return nil;
}

@end

NS_ASSUME_NONNULL_END
