//
//  PGPSecretKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import "PGPS2K.h"

@interface PGPSecretKeyPacket : PGPPublicKeyPacket <NSCopying>

@property (assign, readonly, nonatomic) BOOL isEncryptedWithPassword;
@property (assign) PGPS2KUsage s2kUsage;
@property (strong) PGPS2K *s2k;
@property (assign) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (strong, readonly) NSData *ivData;

/**
 *  Decrypt packet
 *
 *  @param passphrase Password
 *  @param error      error
 *
 *  @return Decrypted key on success
 */
- (PGPSecretKeyPacket *) decryptedKeyPacket:(NSString *)passphrase error:(NSError * __autoreleasing *)error;

- (PGPMPI *) secretMPI:(NSString *)identifier;
- (NSData *) decryptData:(NSData *)data withPublicKeyAlgorithm:(PGPPublicKeyAlgorithm)publicKeyAlgorithm;

@end
