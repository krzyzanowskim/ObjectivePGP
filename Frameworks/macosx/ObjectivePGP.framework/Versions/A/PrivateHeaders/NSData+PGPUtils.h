//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (PGPUtils)

- (UInt16)pgp_Checksum;
- (UInt32)pgp_CRC24;
- (NSData *)pgp_MD5;
- (NSData *)pgp_SHA1;
- (NSData *)pgp_SHA224;
- (NSData *)pgp_SHA256;
- (NSData *)pgp_SHA384;
- (NSData *)pgp_SHA512;
- (NSData *)pgp_RIPEMD160;

+ (NSData *)dataWithValue:(NSValue *)value;

- (NSData *)pgp_HashedWithAlgorithm:(PGPHashAlgorithm)hashAlgorithm;
- (nullable NSData *)pgp_encryptBlockWithSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData;

@end

NS_ASSUME_NONNULL_END
