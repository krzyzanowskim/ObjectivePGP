//
//  PGPPublicKeyEncryptedSessionKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "PGPExportableProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPKeyID, PGPPublicKeyPacket, PGPSecretKeyPacket;

@interface PGPPublicKeyEncryptedSessionKeyPacket : PGPPacket <NSCopying, PGPExportable>
@property (nonatomic) UInt8 version;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, getter=isEncryptedWithPassword) BOOL encryptedWithPassword;
@property (nonatomic) PGPKeyID *keyID;

- (BOOL)encrypt:(PGPPublicKeyPacket *)publicKeyPacket sessionKeyData:(NSData *)sessionKeyData sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm error:(NSError *__autoreleasing *)error;
- (nullable NSData *)decryptSessionKeyData:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm *)sessionKeyAlgorithm error:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
