//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPKey.h>

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(KeyGenerator) @interface PGPKeyGenerator : NSObject

@property (nonatomic) int keyBitsLength;
@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPSymmetricAlgorithm cipherAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) PGPCurve curveKind;
@property (nonatomic) UInt8 version;
@property (nonatomic) NSDate *createDate;

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase;

- (instancetype)initWithAlgorithm:(PGPPublicKeyAlgorithm)algorithm keyBitsLength:(int)bits cipherAlgorithm:(PGPSymmetricAlgorithm)cipherAlgorithm hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

@end

NS_ASSUME_NONNULL_END
