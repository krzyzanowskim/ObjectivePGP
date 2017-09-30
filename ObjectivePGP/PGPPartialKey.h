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
@interface PGPPartialKey : NSObject <PGPExportable, NSCopying>

@property (nonatomic, readonly) PGPPartialKeyType type;
@property (nonatomic, copy) PGPPacket *primaryKeyPacket;
@property (nonatomic, readonly) BOOL isEncrypted;
@property (nonatomic, copy) NSArray<PGPUser *> *users;
@property (nonatomic, copy) NSArray<PGPPartialSubKey *> *subKeys; // TODO: nullable
@property (nonatomic, nullable, copy) NSArray<PGPSignaturePacket *> *directSignatures;
@property (nonatomic, nullable, readonly) PGPSignaturePacket *revocationSignature;
@property (nonatomic, nullable, readonly) NSDate *expirationDate;

@property (nonatomic, readonly) PGPKeyID *keyID;
@property (nonatomic, readonly) PGPFingerprint *fingerprint;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets NS_DESIGNATED_INITIALIZER;

/**
 *  Decrypts all secret key and subkey packets
 *  Warning: It is not good idea to keep decrypted key around
 *
 *  @param passphrase Passphrase
 *  @param error      error
 *
 *  @return Decrypted key, or `nil`.
 */
- (nullable PGPPartialKey *)decryptedWithPassphrase:(NSString *)passphrase error:(NSError *__autoreleasing *)error;

/**
 *  Signing key packet
 *
 *  @return PGPSecureKeyPacket that can be used to signing
 */
@property (nonatomic, nullable, readonly) PGPPacket *signingKeyPacket;

- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID;
- (nullable PGPPacket *)encryptionKeyPacket:(NSError *__autoreleasing *)error;
- (nullable PGPSecretKeyPacket *)decryptionPacketForKeyID:(PGPKeyID *)keyID error:(NSError *__autoreleasing *)error;

- (NSArray<PGPPacket *> *)allKeyPackets;
- (PGPSymmetricAlgorithm)preferredSymmetricAlgorithm;
+ (PGPSymmetricAlgorithm)preferredSymmetricAlgorithmForKeys:(NSArray<PGPPartialKey *> *)keys;

-(instancetype)copyWithZone:(nullable NSZone *)zone NS_REQUIRES_SUPER;

@end

NS_ASSUME_NONNULL_END
