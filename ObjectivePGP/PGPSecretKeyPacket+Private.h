//
//  PGPSecretKeyPacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 09/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket+Private.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSecretKeyPacket ()

@property (nonatomic, readwrite) PGPS2KUsage s2kUsage;
@property (nonatomic, /* copy, */ readwrite) PGPS2K *s2k;
@property (nonatomic, readwrite) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, copy, readwrite) NSData *ivData;
@property (nonatomic, copy) NSArray *secretMPIArray; // decrypted MPI
@property (nonatomic, copy) NSData *encryptedMPIsPartData; // after decrypt -> secretMPIArray

@end

NS_ASSUME_NONNULL_END
