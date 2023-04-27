//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPublicKeyPacket.h"
#import "PGPCurveOID.h"
#import "PGPCurveKDFParameters.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPPublicKeyPacket ()

@property (nonatomic, readwrite) UInt8 version;
@property (nonatomic, readwrite) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, copy, readwrite) NSDate *createDate;
@property (nonatomic, readwrite) UInt16 V3validityPeriod;

@property (nonatomic, copy) NSArray<PGPMPI *> *publicMPIs;
@property (nonatomic, nullable) PGPCurveOID *curveOID; // Available for ECC key
@property (nonatomic, nullable) PGPCurveKDFParameters *curveKDFParameters; // Available for ECC key
@end

NS_ASSUME_NONNULL_END
