//
//  OpenPGPPublicKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 6

#import "PGPFingerprint.h"
#import "PGPKeyID.h"
#import "PGPPacketFactory.h"
#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPMPI;

@interface PGPPublicKeyPacket : PGPPacket <NSCopying, PGPExportable>

@property (nonatomic, readonly) UInt8 version;
@property (nonatomic, readonly) NSDate *createDate;
@property (nonatomic, readonly) UInt16 V3validityPeriod; // obsolete
@property (nonatomic, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, copy, readonly) NSArray<PGPMPI *> *publicMPIArray;

// generated properties
@property (nonatomic, readonly) NSUInteger keySize;
@property (nonatomic, readonly) PGPFingerprint *fingerprint;
@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSData *)exportKeyPacketOldStyle;
- (NSData *)buildKeyBodyData:(BOOL)forceV4;

- (nullable PGPMPI *)publicMPI:(NSString *)identifier;
- (nullable NSData *)encryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm;

@end

NS_ASSUME_NONNULL_END
