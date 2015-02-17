//
//  PGPSignatureSubpacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 20/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(UInt8, PGPSignatureSubpacketType) {
    PGPSignatureSubpacketTypeSignatureCreationTime         = 2, // OK
    PGPSignatureSubpacketTypeSignatureExpirationTime       = 3, // OK
    PGPSignatureSubpacketTypeExportableCertification       = 4, //
    PGPSignatureSubpacketTypeTrustSignature                = 5,
    PGPSignatureSubpacketTypeRegularExpression             = 6, // TODO
    PGPSignatureSubpacketTypeRevocable                     = 7,
    PGPSignatureSubpacketTypeKeyExpirationTime             = 9,
    PGPSignatureSubpacketTypePreferredSymetricAlgorithm    = 11,
    PGPSignatureSubpacketTypeRevocationKey                 = 12, // TODO
    PGPSignatureSubpacketTypeIssuerKeyID                   = 16,
    PGPSignatureSubpacketTypeNotationData                  = 20, // TODO
    PGPSignatureSubpacketTypePreferredHashAlgorithm        = 21,
    PGPSignatureSubpacketTypePreferredCompressionAlgorithm = 22,
    PGPSignatureSubpacketTypeKeyServerPreference           = 23,
    PGPSignatureSubpacketTypePreferredKeyServer            = 24,
    PGPSignatureSubpacketTypePrimaryUserID                 = 25,
    PGPSignatureSubpacketTypePolicyURI                     = 26,
    PGPSignatureSubpacketTypeKeyFlags                      = 27,
    PGPSignatureSubpacketTypeSignerUserID                  = 28,
    PGPSignatureSubpacketTypeReasonForRevocation           = 29, // TODO
    PGPSignatureSubpacketTypeFeatures                      = 30,
    PGPSignatureSubpacketTypeSignatureTarget               = 31, // TODO
    PGPSignatureSubpacketTypeEmbeddedSignature             = 32  // TODO
};

// 5.2.3.17.  Key Server Preferences
typedef NS_ENUM(UInt8, PGPKeyServerPreferenceFlags) {
    PGPKeyServerPreferenceNoModify = 0x80 // No-modify
};

@interface PGPSignatureSubpacket : NSObject
@property (assign) PGPSignatureSubpacketType type;
@property (assign) NSUInteger totalLength;
@property (assign, getter=isCritical) BOOL critical;
@property (strong) id value;

+ (instancetype) readFromStream:(NSInputStream *)inputStream data:(NSData * __autoreleasing *)readData error:(NSError * __autoreleasing *)error;
- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError *__autoreleasing *)error;
@end
