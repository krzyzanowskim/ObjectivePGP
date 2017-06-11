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

@interface PGPSecretKeyPacket : PGPPublicKeyPacket <NSCopying>

@property (nonatomic, readonly) BOOL isEncryptedWithPassword;
@property (nonatomic, readonly) PGPS2KUsage s2kUsage;
@property (nonatomic, readonly) PGPS2K *s2k;
@property (nonatomic, readonly) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, copy, readonly) NSData *ivData;

/**
 *  Decrypt packet
 *
 *  @param passphrase Password
 *  @param error      error
 *
 *  @return Decrypted key on success
 */
- (nullable PGPSecretKeyPacket *)decryptedKeyPacket:(NSString *)passphrase error:(NSError * __autoreleasing *)error;

- (PGPMPI *)secretMPI:(NSString *)identifier;
- (NSData *)decryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm;

@end

NS_ASSUME_NONNULL_END
