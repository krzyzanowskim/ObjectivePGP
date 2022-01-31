//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPCurveKDFParameters.h"
#import <ObjectivePGP/PGPMacros+Private.h>
#import "NSMutableData+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCurveKDFParameters ()

@property (assign, nonatomic, readwrite) PGPHashAlgorithm hashAlgorithm;
@property (assign, nonatomic, readwrite) PGPSymmetricAlgorithm symmetricAlgorithm;

@end

@implementation PGPCurveKDFParameters

- (instancetype)initWithHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm {
    if ((self = [super init])) {
        _hashAlgorithm = hashAlgorithm;
        _symmetricAlgorithm = symmetricAlgorithm;
    }
    return self;
}

- (nullable NSData *)export:(NSError * _Nullable __autoreleasing * _Nullable)error {
    let data = [NSMutableData data];

    UInt8 length = 0x03;
    [data appendBytes:&length length:1];
    UInt8 reserved = 0x01;
    [data appendBytes:&reserved length:1];
    [data appendBytes:&_hashAlgorithm length:1];
    [data appendBytes:&_symmetricAlgorithm length:1];

    return data;
}

+ (instancetype)defaultParameters {
    return [[PGPCurveKDFParameters alloc] initWithHashAlgorithm:PGPHashSHA256 symmetricAlgorithm:PGPSymmetricAES128];
}

@end

NS_ASSUME_NONNULL_END
