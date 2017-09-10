//
//  PGPS2K.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPTypes.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPS2K : NSObject <NSCopying>

@property (nonatomic, readonly) PGPS2KSpecifier specifier;
@property (nonatomic, readonly) PGPHashAlgorithm hashAlgorithm;
// random 8 bytes.
@property (nonatomic, copy, readonly) NSData *salt;
// Iteration count.
@property (nonatomic) UInt32 iterationsCount;
// calculated
@property (nonatomic, readonly) UInt32 codedCount;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithSpecifier:(PGPS2KSpecifier)specifier hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm NS_DESIGNATED_INITIALIZER;

+ (PGPS2K *)S2KFromData:(NSData *)data atPosition:(NSUInteger)position length:(nullable NSUInteger *)length;

- (nullable NSData *)buildKeyDataForPassphrase:(NSData *)passphrase prefix:(nullable NSData *)prefix salt:(NSData *)salt codedCount:(UInt32)codedCount;
- (nullable NSData *)produceSessionKeyWithPassphrase:(NSString *)passphrase symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
- (nullable NSData *)export:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
