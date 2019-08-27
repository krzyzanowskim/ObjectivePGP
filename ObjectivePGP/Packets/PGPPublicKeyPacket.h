//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  Tag 6

#import "PGPPacketFactory.h"
#import "PGPFingerprint.h"
#import "PGPKeyID.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPMPI, PGPBigNum;

@interface PGPPublicKeyPacket : PGPPacket <NSCopying, PGPExportable>

@property (nonatomic, readonly) UInt8 version;
@property (nonatomic, readonly) NSDate *createDate;
@property (nonatomic, readonly) UInt16 V3validityPeriod; // obsolete
@property (nonatomic, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;

// generated properties
@property (nonatomic, readonly) NSUInteger keySize;
@property (nonatomic, readonly) PGPFingerprint *fingerprint;
@property (nonatomic, readonly) PGPKeyID *keyID;
@property (nonatomic, readonly) BOOL isSupported;

- (NSData *)exportKeyPacketOldStyle;
- (NSData *)buildKeyBodyData:(BOOL)forceV4;

- (nullable PGPMPI *)publicMPI:(NSString *)identifier;
- (nullable NSArray<PGPMPI *> *)encryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm;

@end

NS_ASSUME_NONNULL_END
