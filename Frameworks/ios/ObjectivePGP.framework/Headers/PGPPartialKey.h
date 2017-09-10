//
//  PGPTransferableKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPExportableProtocol.h"
#import "PGPKeyID.h"
#import "PGPPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, PGPPartialKeyType) { PGPPartialKeyUnknown = 0, PGPPartialKeySecret = 1, PGPPartialKeyPublic = 2 };

@class PGPSecretKeyPacket, PGPPartialSubKey;

/// Single Private or Public key.
@interface PGPPartialKey : NSObject <PGPExportable>

@property (nonatomic, readonly) PGPPartialKeyType type;
@property (nonatomic) PGPPacket *primaryKeyPacket;
@property (nonatomic, readonly) BOOL isEncrypted;
@property (nonatomic, copy) NSArray<PGPUser *> *users;
@property (nonatomic, copy) NSArray<PGPPartialSubKey *> *subKeys; // TODO: nullable
@property (nonatomic, nullable, copy) NSArray<PGPSignaturePacket *> *directSignatures;
@property (nonatomic, nullable) PGPPacket *revocationSignature;
@property (nonatomic, nullable, readonly) NSDate *expirationDate;

@property (nonatomic, readonly) PGPKeyID *keyID;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets NS_DESIGNATED_INITIALIZER;

/**
 *  Decrypts all secret key and subkey packets
 *  Note: After decryption encrypted packets are replaced with new decrypted instances on key.
 *  Warning: It is not good idea to keep decrypted key around
 *
 *  @param passphrase Passphrase
 *  @param error      error
 *
 *  @return YES on success.
 */
- (BOOL)decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error;

/**
 *  Signing key packet
 *
 *  @return PGPSecureKeyPacket that can be used to signing
 */
@property (nonatomic, nullable, readonly) PGPPacket *signingKeyPacket;

- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID;
- (nullable PGPPacket *)encryptionKeyPacket:(NSError *__autoreleasing *)error;
- (nullable PGPSecretKeyPacket *)decryptionKeyPacketWithID:(PGPKeyID *)keyID error:(NSError *__autoreleasing *)error;

- (NSArray<PGPPacket *> *)allKeyPackets;
- (PGPSymmetricAlgorithm)preferredSymmetricAlgorithm;
+ (PGPSymmetricAlgorithm)preferredSymmetricAlgorithmForKeys:(NSArray<PGPPartialKey *> *)keys;

@end

NS_ASSUME_NONNULL_END
