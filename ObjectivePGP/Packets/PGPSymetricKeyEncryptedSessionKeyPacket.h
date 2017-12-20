//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//


#import "PGPPacket.h"
#import "PGPExportableProtocol.h"
#import "PGPEncryptedSessionKeyPacketProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPS2K;

@interface PGPSymetricKeyEncryptedSessionKeyPacket : PGPPacket <PGPEncryptedSessionKeyPacketProtocol, NSCopying, PGPExportable>
@property (nonatomic) UInt8 version;
@property (nonatomic) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (nonatomic, copy) PGPS2K *s2k;
@property (nonatomic, copy, nullable) NSData *encryptedSessionKey;

@end

NS_ASSUME_NONNULL_END
