//
//  PGPS2K.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPS2K : NSObject

@property (nonatomic) PGPS2KSpecifier specifier;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) NSData *salt; // 8 bytes
@property (nonatomic) UInt32 uncodedCount;
@property (nonatomic, readonly) UInt32 codedCount;

@property (nonatomic) NSUInteger length;

+ (PGPS2K *) string2KeyFromData:(NSData *)data atPosition:(NSUInteger)position;
- (NSUInteger) parseS2K:(NSData *)data atPosition:(NSUInteger)position;

- (NSData *) produceSessionKeyWithPassphrase:(NSString *)passphrase keySize:(NSUInteger)keySize;
- (NSData *) export:(NSError *__autoreleasing*)error;

@end
