//
//  PGPPublicKeyPacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 09/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPublicKeyPacket ()

@property (nonatomic, readwrite) UInt8 version;
@property (nonatomic, readwrite) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, copy, readwrite) NSDate *createDate;
//@property (nonatomic, readwrite) PGPFingerprint *fingerprint;
//@property (nonatomic, readwrite) PGPKeyID *keyID;
@property (nonatomic, readwrite) UInt16 V3validityPeriod;
@property (nonatomic, copy, readwrite) NSArray<PGPMPI *> *publicMPIArray;

@end

NS_ASSUME_NONNULL_END
