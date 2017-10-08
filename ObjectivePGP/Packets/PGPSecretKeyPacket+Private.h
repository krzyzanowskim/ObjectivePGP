//
//  PGPSecretKeyPacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 09/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket+Private.h"
#import "PGPS2K.h"
#import "PGPSecretKeyPacket.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSecretKeyPacket ()

@property (nonatomic, readwrite) PGPS2KUsage s2kUsage;
@property (nonatomic, /* copy, */ readwrite) PGPS2K *s2k;
@property (nonatomic, readwrite) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, copy, nullable, readwrite) NSData *ivData;
@property (nonatomic, copy) NSArray<PGPMPI *> *secretMPIArray; // decrypted MPI
@property (nonatomic, nullable, copy) NSData *encryptedMPIPartData; // after decrypt -> secretMPIArray

@end

NS_ASSUME_NONNULL_END
