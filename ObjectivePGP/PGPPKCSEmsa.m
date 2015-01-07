//
//  PGPPKCS.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 22/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPKCSEmsa.h"
#import "PGPTypes.h"
#import "NSData+PGPUtils.h"
#import "PGPCryptoUtils.h"

static UInt8 prefix_md5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10
};

static UInt8 prefix_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
};

static UInt8 prefix_sha224[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1C
};

static UInt8 prefix_sha256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

static UInt8 prefix_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};

static UInt8 prefix_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};

static UInt8 prefix_ripemd160[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24,
    0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14
};


@implementation PGPPKCSEmsa

/**
 *  create a EMSA-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3})
 *
 *  @param hashAlgorithm Hash algoritm
 *  @param m       message to be encoded
 *  @param emLen   intended length in octets of the encoded message
 *
 *  @return encoded message
 */
+ (NSData *) encode:(PGPHashAlgorithm)hashAlgorithm message:(NSData *)m encodedMessageLength:(NSUInteger)emLength error:(NSError * __autoreleasing *)error
{
    NSMutableData *tData = [NSMutableData data]; // prefix + hash
    switch (hashAlgorithm) {
        case PGPHashMD5:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_md5 length:sizeof(prefix_md5)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_MD5]];
        }
            break;
        case PGPHashSHA1:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_sha1 length:sizeof(prefix_sha1)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_SHA1]];
        }
            break;
        case PGPHashSHA224:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_sha224 length:sizeof(prefix_sha224)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_SHA224]];
        }
            break;
        case PGPHashSHA256:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_sha256 length:sizeof(prefix_sha256)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_SHA256]];
        }
            break;
        case PGPHashSHA384:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_sha384 length:sizeof(prefix_sha384)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_SHA384]];
        }
            break;
        case PGPHashSHA512:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_sha512 length:sizeof(prefix_sha512)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_SHA512]];
        }
            break;
        case PGPHashRIPEMD160:
        {
            NSData *hashPrefixData = [NSData dataWithBytes:prefix_ripemd160 length:sizeof(prefix_ripemd160)];
            [tData appendData:hashPrefixData];
            [tData appendData:[m pgp_RIPEMD160]];
        }
            break;
        default:
            NSAssert(false,@"Missing implementation");
            break;
    }
    
    if (emLength < tData.length + 11) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"intended encoded message length too short"}];
        }
        return nil;
    }

    // Generate an octet string PS consisting of emLen - tLen - 3
    // octets with hexadecimal value 0xFF.  The length of PS will be at
    // least 8 octets.
    NSMutableData *psData = [NSMutableData data];
    UInt8 ff = 0xff;
    for (NSUInteger i = 0; i < emLength - tData.length - 3; i++) {
        [psData appendBytes:&ff length:1];
    }

    NSMutableData *emData = [NSMutableData data];
    UInt8 emPrefix[] = {0x00, 0x01};
    UInt8 emSuffix[] = {0x00};
    [emData appendBytes:emPrefix length:sizeof(emPrefix)];
    [emData appendData:psData];
    [emData appendBytes:emSuffix length:sizeof(emSuffix)];
    [emData appendData:tData];

    return [emData copy];
}

@end
