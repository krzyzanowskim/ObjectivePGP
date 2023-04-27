//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPExportableProtocol.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPS2K : NSObject <NSCopying, PGPExportable>

@property (nonatomic, readonly) PGPS2KSpecifier specifier;
@property (nonatomic, readonly) PGPHashAlgorithm hashAlgorithm;
// random 8 bytes.
@property (nonatomic, copy, readonly) NSData *salt;
// Iteration count.
@property (nonatomic) UInt32 iterationsCount;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithSpecifier:(PGPS2KSpecifier)specifier hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm NS_DESIGNATED_INITIALIZER;

+ (PGPS2K *)S2KFromData:(NSData *)data atPosition:(NSUInteger)position length:(nullable NSUInteger *)length;

- (nullable NSData *)buildKeyDataForPassphrase:(NSData *)passphrase prefix:(nullable NSData *)prefix salt:(NSData *)salt codedCount:(UInt32)codedCount;
- (nullable NSData *)produceSessionKeyWithPassphrase:(NSString *)passphrase symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
