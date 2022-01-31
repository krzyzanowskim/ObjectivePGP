//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPCurveOID.h>
#import <ObjectivePGP/PGPCurveKDFParameters.h>

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(KeySpec) @interface PGPKeySpec : NSObject

@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPCurveOID *curve;
@property (nonatomic) PGPCurveKDFParameters *kdfParameters;
@property (nonatomic) int keyBitsLength;

- (instancetype)initWithKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm withCurve:(PGPCurve)curve withKdfParameters:(PGPCurveKDFParameters*)kdfParameters;

- (instancetype)initWithKeyAlgorithm:(PGPPublicKeyAlgorithm)algorithm withKeyBitsLength:(int)keyBitsLength;

@end

NS_ASSUME_NONNULL_END
