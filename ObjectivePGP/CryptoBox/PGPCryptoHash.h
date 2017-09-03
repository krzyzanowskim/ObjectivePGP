//
//  PGPCryptoHash.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 21/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^PGPUpdateBlock)(void (^update)(const void *data, int lenght));

NSData *_Nullable PGPCalculateHash(PGPHashAlgorithm algorithm, PGP_NOESCAPE PGPUpdateBlock update);

NSData *_Nullable PGPmd5(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha1(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha224(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha256(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha384(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha512(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPripemd160(PGP_NOESCAPE PGPUpdateBlock update);

NS_ASSUME_NONNULL_END
