//
//  PGPCryptoHash.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 21/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "ObjectivePGP.h"

NS_ASSUME_NONNULL_BEGIN

typedef void(^PGPUpdateBlock)(void(^update)(const void *data, int lenght));

NSData * _Nullable PGPCalculateHash(PGPHashAlgorithm algorithm, NOESCAPE PGPUpdateBlock update);

NSData * _Nullable PGPmd5(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPsha1(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPsha224(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPsha256(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPsha384(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPsha512(NOESCAPE PGPUpdateBlock update);
NSData * _Nullable PGPripemd160(NOESCAPE PGPUpdateBlock update);

NS_ASSUME_NONNULL_END
