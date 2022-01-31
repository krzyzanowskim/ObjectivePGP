//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPKeySpec.h"

@implementation PGPKeySpec

- (instancetype)initWithKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm withCurve:(PGPCurve)curve withKdfParameters:(PGPCurveKDFParameters*)kdfParameters {
    if ((self = [super init])) {
        _keyAlgorithm = algorithm;
        _curve = [[PGPCurveOID alloc] initWithCurveKind:curve];
        _kdfParameters = kdfParameters;
        _keyBitsLength = 0;
    }
    return self;
}

- (instancetype)initWithKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm withKeyBitsLength:(int)keyBitsLength {
    if ((self = [super init])) {
        _keyAlgorithm = algorithm;
        _curve = nil;
        _kdfParameters = nil;
        _keyBitsLength = keyBitsLength;
    }
    return self;
}

@end
