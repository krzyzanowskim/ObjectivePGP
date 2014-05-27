//
//  OpenPGPPublicKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 6

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPPacketFactory.h"
#import "PGPKeyID.h"
#import "PGPFingerprint.h"

@class PGPMPI;

@interface PGPPublicKeyPacket : PGPPacket

@property (assign, readonly) UInt8 version;
@property (assign, readonly) UInt32 timestamp;
@property (assign, readonly) UInt16 V3validityPeriod; // obsolete
@property (assign, readonly) PGPPublicKeyAlgorithm publicKeyAlgorithm;

@property (assign, readonly) NSUInteger keySize;

@property (strong, nonatomic, readonly) PGPFingerprint *fingerprint;
@property (strong, nonatomic, readonly) PGPKeyID *keyID;

- (NSData *) exportPacket:(NSError *__autoreleasing*)error;
- (NSData *) exportPublicPacketOldStyle;

- (NSData *) buildPublicKeyBodyData:(BOOL)forceV4;

- (PGPMPI *) publicMPI:(NSString *)identifier;

@end
