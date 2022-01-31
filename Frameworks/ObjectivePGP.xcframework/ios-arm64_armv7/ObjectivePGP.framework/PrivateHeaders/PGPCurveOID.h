//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPExportableProtocol.h>
#import <ObjectivePGP/PGPTypes.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(CurveOID) @interface PGPCurveOID : NSObject <PGPExportable>

@property (assign, nonatomic, readonly) PGPCurve curveKind;

PGP_EMPTY_INIT_UNAVAILABLE;

- (nullable instancetype)initWithIdentifierData:(NSData *)identifierData NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCurveKind:(PGPCurve)kind;

@end

NS_ASSUME_NONNULL_END
