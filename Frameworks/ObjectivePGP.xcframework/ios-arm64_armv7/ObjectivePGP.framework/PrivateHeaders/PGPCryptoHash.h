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

typedef void (^PGPUpdateBlock)(void (^update)(const void *data, int lenght));

NSData *_Nullable PGPCalculateHash(PGPHashAlgorithm algorithm, NS_NOESCAPE PGPUpdateBlock update);

NSData *_Nullable PGPmd5(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha1(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha224(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha256(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha384(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha512(NS_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPripemd160(NS_NOESCAPE PGPUpdateBlock update);

NS_ASSUME_NONNULL_END
