//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey;

NS_SWIFT_NAME(KeyGenerator) @interface PGPKeyGenerator : NSObject

@property (nonatomic) int keyBitsLength;
@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPSymmetricAlgorithm cipherAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) UInt8 version;
@property (nonatomic) NSDate *createDate;

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase;

@end

NS_ASSUME_NONNULL_END
