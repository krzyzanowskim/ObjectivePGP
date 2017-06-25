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

@class PGPMPI;

@interface PGPPublicKeyPacket : PGPPacket <NSCopying>

@property (nonatomic, readonly) UInt8 version;
@property (nonatomic, readonly) NSDate *createDate;
@property (nonatomic, readonly) UInt16 V3validityPeriod; // obsolete
@property (nonatomic, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, readwrite) NSArray *publicMPIArray;

@property (nonatomic, readonly) NSUInteger keySize;

@property (nonatomic, readonly) PGPFingerprint *fingerprint;
@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSData *)export:(NSError *__autoreleasing *)error;
- (NSData *)exportPublicPacketOldStyle;

- (NSData *)buildPublicKeyBodyData:(BOOL)forceV4;

- (PGPMPI *)publicMPI:(NSString *)identifier;
- (NSData *)encryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm;

@end
