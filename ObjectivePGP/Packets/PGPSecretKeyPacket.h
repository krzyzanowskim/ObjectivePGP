//
//  PGPSecretKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import "PGPS2K.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPSecretKeyPacket : PGPPublicKeyPacket <NSCopying, PGPExportable>

@property (nonatomic, readonly) PGPS2KUsage s2kUsage;
@property (nonatomic, readonly) PGPS2K *s2k;
@property (nonatomic, readonly) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, nullable, copy, readonly) NSData *ivData;
@property (nonatomic, getter=isEncryptedWithPassphrase, readonly) BOOL encryptedWithPassphrase;

/**
 *  Decrypt packet
 *
 *  @param passphrase Passphrase
 *  @param error      error
 *
 *  @return Decrypted key on success
 */
- (nullable PGPSecretKeyPacket *)decryptedKeyPacket:(NSString *)passphrase error:(NSError *__autoreleasing *)error;

- (nullable PGPMPI *)secretMPI:(NSString *)identifier;

@end

NS_ASSUME_NONNULL_END
