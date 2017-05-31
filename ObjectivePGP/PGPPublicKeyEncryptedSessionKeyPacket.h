//
//  PGPPublicKeyEncryptedSessionKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@class PGPKeyID, PGPPublicKeyPacket, PGPSecretKeyPacket;

@interface PGPPublicKeyEncryptedSessionKeyPacket : PGPPacket <NSCopying>
@property (nonatomic) UInt8 version;
@property (nonatomic) PGPKeyID *keyID;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, getter = isEncrypted) BOOL encrypted;

- (BOOL) encrypt:(PGPPublicKeyPacket *)publicKeyPacket sessionKeyData:(NSData *)sessionKeyData sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm error:(NSError * __autoreleasing *)error;
- (NSData *) decryptSessionKeyData:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm *)sessionKeyAlgorithm error:(NSError * __autoreleasing *)error;

@end
