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
        _symmetricKey = nil;
    }
    return self;
}

- (nonnull id)copyWithZone:(nullable NSZone *)zone {
    PGPPublicKeyEncryptedSessionKeyParams *duplicate = [[self.class alloc] init];
    duplicate.MPIs = self.MPIs;
    duplicate.symmetricKey = self.symmetricKey;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
