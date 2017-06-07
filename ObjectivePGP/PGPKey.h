//
//  PGPTransferableKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPPacket.h"
#import "PGPKeyID.h"
#import "PGPSignaturePacket.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, PGPKeyType) {
    PGPKeyUnknown = 0,
    PGPKeySecret  = 1,
    PGPKeyPublic  = 2
};

@class PGPSecretKeyPacket;

/// Single Private or Public key.
@interface PGPKey : NSObject

@property (nonatomic, readonly) PGPKeyType type;
@property (nonatomic) PGPPacket  *primaryKeyPacket;
@property (nonatomic, readonly) BOOL isEncrypted;
@property (nonatomic, copy) NSArray<PGPUser *> *users;
@property (nonatomic, copy) NSArray *subKeys; // TODO: nullable
@property (nonatomic, nullable, copy) NSArray<PGPSignaturePacket *> *directSignatures;
@property (nonatomic, nullable) PGPPacket *revocationSignature;

@property (nonatomic, readonly) PGPKeyID *keyID;

- (instancetype) initWithPackets:(NSArray<PGPPacket *> *)packets;

/**
 *  Decrypts all secret key and subkey packets
 *  Note: After decryption encrypted packets are replaced with new decrypted instances on key.
 *  Warning: It is not good idea to keep decrypted key around
 *
 *  @param passphrase Password
 *  @param error      error
 *
 *  @return YES on success.
 */
- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error;

/**
 *  Signing key packet
 *
 *  @return PGPSecureKeyPacket that can be used to signing
 */
@property (nonatomic, nullable, readonly) PGPPacket *signingKeyPacket;

- (nullable PGPPacket *)signingKeyPacketWithKeyID:(PGPKeyID *)keyID;
- (nullable PGPPacket *)encryptionKeyPacket:(NSError * __autoreleasing *)error;
- (nullable PGPSecretKeyPacket *)decryptionKeyPacketWithID:(PGPKeyID *)keyID error:(NSError * __autoreleasing *)error;

- (NSArray<PGPPacket *> *) allKeyPackets;
- (PGPSymmetricAlgorithm) preferredSymmetricAlgorithm;
+ (PGPSymmetricAlgorithm) preferredSymmetricAlgorithmForKeys:(NSArray<PGPKey *> *)keys;

/**
 *  Export to transferable key packets sequence
 *
 *  @return Data
 */
- (NSData *) export:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
