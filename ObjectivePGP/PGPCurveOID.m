//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPCurveOID.h"
#import <ObjectivePGP/PGPMacros+Private.h>
#import "NSArray+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPTypes.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

static UInt8 pgp_curve_identifier_p256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static UInt8 pgp_curve_identifier_p384[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
static UInt8 pgp_curve_identifier_p521[] = {0x2B, 0x81, 0x04, 0x00, 0x23};
static UInt8 pgp_curve_identifier_brainpoolP256r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
static UInt8 pgp_curve_identifier_brainpoolP512r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
static UInt8 pgp_curve_identifier_ed25519[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01};
static UInt8 pgp_curve_identifier_curve25519[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01};

@interface PGPCurveOID ()

@property (assign, nonatomic, readwrite) PGPCurve curveKind;

@end

@implementation PGPCurveOID

- (nullable instancetype)initWithIdentifierData:(NSData *)identifierData {
    if ((self = [super init])) {
        // recognize type
        if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_p256 length:sizeof(pgp_curve_identifier_p256)])) {
            _curveKind = PGPCurveP256;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_p384 length:sizeof(pgp_curve_identifier_p384)])) {
            _curveKind = PGPCurveP384;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_p521 length:sizeof(pgp_curve_identifier_p521)])) {
            _curveKind = PGPCurveP521;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_brainpoolP256r1 length:sizeof(pgp_curve_identifier_brainpoolP256r1)])) {
            _curveKind = PGPCurveBrainpoolP256r1;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_brainpoolP512r1 length:sizeof(pgp_curve_identifier_brainpoolP512r1)])) {
            _curveKind = PGPCurveBrainpoolP512r1;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_ed25519 length:sizeof(pgp_curve_identifier_ed25519)])) {
            _curveKind = PGPCurveEd25519;
        } else if (PGPEqualObjects(identifierData, [NSData dataWithBytes:pgp_curve_identifier_curve25519 length:sizeof(pgp_curve_identifier_curve25519)])) {
            _curveKind = PGPCurve25519;
        } else {
            return nil;
        }
    }
    return self;
}

- (nullable instancetype)initWithCurveKind:(PGPCurve)kind {
    if ((self = [self init])) {
        _curveKind = kind;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@. curveKind: %@", super.description, @(self.curveKind)];
}

- (nullable NSData *)export:(NSError * _Nullable __autoreleasing * _Nullable)error {
    let bodyData = [NSMutableData data];

    switch (self.curveKind) {
        case PGPCurveP256: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_p256);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_p256 length:length];
        } break;
        case PGPCurveP384: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_p384);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_p384 length:length];
        } break;
        case PGPCurveP521: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_p521);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_p521 length:length];
        } break;
        case PGPCurveBrainpoolP256r1: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_brainpoolP256r1);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_brainpoolP256r1 length:length];
        } break;
        case PGPCurveBrainpoolP512r1: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_brainpoolP512r1);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_brainpoolP512r1 length:length];
        } break;
        case PGPCurveEd25519: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_ed25519);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_ed25519 length:length];
        } break;
        case PGPCurve25519: {
            UInt8 length = (UInt8)sizeof(pgp_curve_identifier_curve25519);
            [bodyData appendBytes:&length length:1];
            [bodyData appendBytes:pgp_curve_identifier_curve25519 length:length];
        } break;
    }

    return bodyData;
}

@end

NS_ASSUME_NONNULL_END
