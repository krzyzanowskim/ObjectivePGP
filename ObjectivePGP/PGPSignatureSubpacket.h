//
//  PGPSignatureSubpacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 20/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(UInt8, PGPSignatureSubpacketType) {
    PGPSignatureSubpacketTypeSignatureCreationTime         = 2,
    PGPSignatureSubpacketTypeSignatureExpirationTime       = 3,
    PGPSignatureSubpacketTypeExportableCertification       = 4,
    PGPSignatureSubpacketTypeTrustSignature                = 5,
    PGPSignatureSubpacketTypeRegularExpression             = 6,
    PGPSignatureSubpacketTypeRevocable                     = 7,
    PGPSignatureSubpacketTypeKeyExpirationTime             = 9,
    PGPSignatureSubpacketTypePreferredSymetricAlgorithm    = 11,
    PGPSignatureSubpacketTypeRevocationKey                 = 12,
    PGPSignatureSubpacketTypeIssuerKeyID                   = 16,
    PGPSignatureSubpacketTypeNotationData                  = 20,
    PGPSignatureSubpacketTypePreferredHashAlgorithm        = 21,
    PGPSignatureSubpacketTypePreferredCompressionAlgorithm = 22,
    PGPSignatureSubpacketTypeKeyServerPreference           = 23,
    PGPSignatureSubpacketTypePreferredKeyServer            = 24,
    PGPSignatureSubpacketTypePrimaryUserID                 = 25,
    PGPSignatureSubpacketTypePolicyURI                     = 26,
    PGPSignatureSubpacketTypeKeyFlags                      = 27,
    PGPSignatureSubpacketTypeSignerUserID                  = 28,
    PGPSignatureSubpacketTypeReasonForRevocation           = 29,
    PGPSignatureSubpacketTypeFeatures                      = 30,
    PGPSignatureSubpacketTypeSignatureTarget               = 31,
    PGPSignatureSubpacketTypeEmbeddedSignature             = 32
};

@interface PGPSignatureSubpacket : NSObject
@property (assign) PGPSignatureSubpacketType type;
@property (assign) NSUInteger totalLength;
@property (assign, getter=isCritical) BOOL critical;
@property (strong) id value;

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
@end
