//
//  PGPS2K.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFoundation.h"
#import "PGPMacros.h"
#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPS2K : NSObject

@property (nonatomic, readonly) PGPS2KSpecifier specifier;
@property (nonatomic, readonly) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic, readonly) NSData *salt; // random 8 bytes.
@property (nonatomic, readonly) UInt32 uncodedCount;
@property (nonatomic, readonly) UInt32 codedCount;

@property (nonatomic) NSUInteger length;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithSpecifier:(PGPS2KSpecifier)specifier hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm NS_DESIGNATED_INITIALIZER;

+ (PGPS2K *)S2KFromData:(NSData *)data atPosition:(NSUInteger)position;

- (nullable NSData *)produceSessionKeyWithPassphrase:(NSString *)passphrase keySize:(NSUInteger)keySize;
- (nullable NSData *) export:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
