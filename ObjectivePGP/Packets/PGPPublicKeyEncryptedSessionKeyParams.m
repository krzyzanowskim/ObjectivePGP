//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPPublicKeyEncryptedSessionKeyParams.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPPublicKeyEncryptedSessionKeyParams

- (instancetype)init {
    if ((self = [super init])) {
        _MPIs = @[];
        _ECDH_encodedSymmetricKey = nil;
    }
    return self;
}

- (nonnull id)copyWithZone:(nullable NSZone *)zone {
    PGPPublicKeyEncryptedSessionKeyParams *duplicate = [[self.class alloc] init];
    duplicate.MPIs = self.MPIs;
    duplicate.ECDH_encodedSymmetricKey = self.ECDH_encodedSymmetricKey;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
