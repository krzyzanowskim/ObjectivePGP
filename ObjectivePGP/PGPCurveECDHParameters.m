//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPCurveECDHParameters.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCurveECDHParameters ()

@property (assign, nonatomic, readwrite) PGPHashAlgorithm hashAlgorithm;
@property (assign, nonatomic, readwrite) PGPSymmetricAlgorithm symmetricAlgorithm;

@end

@implementation PGPCurveECDHParameters

- (instancetype)initWithHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm {
    if ((self = [super init])) {
        _hashAlgorithm = hashAlgorithm;
        _symmetricAlgorithm = symmetricAlgorithm;
    }
    return self;
}

@end

NS_ASSUME_NONNULL_END
