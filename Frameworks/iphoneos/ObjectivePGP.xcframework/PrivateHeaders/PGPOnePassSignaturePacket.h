//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"
#import "PGPExportableProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPKeyID;

@interface PGPOnePassSignaturePacket : PGPPacket <PGPExportable, NSCopying>

@property (nonatomic) UInt8 version; //  The current version is 3.
@property (nonatomic) PGPSignatureType signatureType;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, copy) PGPKeyID *keyID; // 8
@property (nonatomic) BOOL isNested;

@end

NS_ASSUME_NONNULL_END
