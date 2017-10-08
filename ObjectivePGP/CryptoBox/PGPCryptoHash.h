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

NSData *_Nullable PGPCalculateHash(PGPHashAlgorithm algorithm, PGP_NOESCAPE PGPUpdateBlock update);

NSData *_Nullable PGPmd5(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha1(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha224(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha256(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha384(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPsha512(PGP_NOESCAPE PGPUpdateBlock update);
NSData *_Nullable PGPripemd160(PGP_NOESCAPE PGPUpdateBlock update);

NS_ASSUME_NONNULL_END
