//
//  PGPCommon.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#pragma mark once

static NSString * PGPErrorDomain = @"ObjectivePGP";
static const UInt32 PGPIndeterminateLength = UINT32_MAX;

// 9.4.  Hash Algorithms
typedef NS_ENUM(UInt8, PGPHashAlgorithm) {
    PGPHashMD5       = 1, //MD5  - deprecated
    PGPHashSHA1      = 2, //SHA1 - required
    PGPHashRIPEMD160 = 3, //RIPEMD160
    PGPHashSHA256    = 8, //SHA256
    PGPHashSHA384    = 9, //SHA384
    PGPHashSHA512    = 10,//SHA512
    PGPHashSHA224    = 11 //SHA224
};