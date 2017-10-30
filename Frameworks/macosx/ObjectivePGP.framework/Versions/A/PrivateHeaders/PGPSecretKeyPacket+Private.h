//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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
@property (nonatomic, copy) NSArray<PGPMPI *> *secretMPIs; // decrypted MPI
@property (nonatomic, nullable, copy) NSData *encryptedMPIPartData; // after decrypt -> secretMPIArray

@end

NS_ASSUME_NONNULL_END
