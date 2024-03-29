//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "NSData+PGPUtils.h"
#import "PGPCryptoHash.h"
#import "PGPCryptoUtils.h"
#import "PGPMacros+Private.h"

#import <CommonCrypto/CommonCrypto.h>

#import <openssl/aes.h>
#import <openssl/blowfish.h>
#import <openssl/camellia.h>
#import <openssl/cast.h>
#import <openssl/des.h>
#import <openssl/idea.h>
#import <openssl/ripemd.h>
#import <openssl/sha.h>

NS_ASSUME_NONNULL_BEGIN

@implementation NSData (PGPUtils)

/**
 *  Calculates a 16bit sum of all octets, mod 65536
 *
 *  @return checksum
 */
- (UInt16)pgp_Checksum {
    UInt32 s = 0;
    const UInt8 *bytes = self.bytes;
    for (NSUInteger i = 0; i < self.length; i++) {
        s = (s + (UInt8)bytes[i]);
    }
    s = s % 65536;
    return (UInt16)s;
}

#define CRC24_POLY 0x1864cfbL
#define CRC24_INIT 0xB704CEL

- (UInt32)pgp_CRC24 {
    UInt32 crc = CRC24_INIT;
    NSUInteger len = self.length;
    NSUInteger j = 0;
    const UInt8 *octets = self.bytes;
    for (j = len; j > 0; j--) {
        crc ^= (*octets++) << 16;
        for (int i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000) crc ^= CRC24_POLY;
        }
    }

    return crc & 0xFFFFFFL;
}

- (NSData *)pgp_MD5 {
    return PGPmd5(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_SHA1 {
    return PGPsha1(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_SHA224 {
    return PGPsha224(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_SHA256 {
    return PGPsha256(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_SHA384 {
    return PGPsha384(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_SHA512 {
    return PGPsha512(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_RIPEMD160 {
    return PGPripemd160(^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_HashedWithAlgorithm:(PGPHashAlgorithm)hashAlgorithm {
    return PGPCalculateHash(hashAlgorithm, ^(void (^update)(const void *, int)) {
        update(self.bytes, (int)self.length);
    });
}

- (NSData *)pgp_reversed {
    let reversed = [[NSMutableData alloc] initWithCapacity:self.length];
    for (int i = (int)self.length - 1; i >= 0; i--) {
        [reversed appendBytes:&self.bytes[i] length:1];
    }
    return reversed;
}

- (NSData *)pgp_PKCS5Padded {
    // Add PKCS5 padding
    let padding_len = 8 - (self.length % 8);
    let paddedData = [NSMutableData dataWithData:self];
    let padding_buf = calloc(padding_len, 1);
    pgp_defer {
        free(padding_buf);
    };
    memset(padding_buf, padding_len, padding_len);
    [paddedData appendBytes:padding_buf length:padding_len];
    return paddedData;
}

// xor up to the last byte of the shorter data
+ (NSData *)xor:(NSData *)d1 d2:(NSData *)d2 {
    let outLen = MIN(d1.length, d2.length);
    let output = [NSMutableData dataWithLength:outLen];
    let outputBuf = (uint8_t *)output.mutableBytes;
    let d1buf = (uint8_t *)d1.bytes;
    let d2buf = (uint8_t *)d2.bytes;
    for (NSUInteger i = 0; i < outLen; i++) {
        outputBuf[i] = d1buf[i] ^ d2buf[i];
    }
    return output;
}

#pragma mark - NSValue

+ (NSData *)dataWithValue:(NSValue *)value {
    NSUInteger size = 0;
    let encoding = [value objCType];
    NSGetSizeAndAlignment(encoding, &size, nil);

    let ptr = calloc(size,1);
    [value getValue:ptr];
    let data = [NSData dataWithBytes:ptr length:size];
    free(ptr);

    return data;
}

- (NSString*)pgpDebugAscii{
    return [[[[[[NSString.alloc initWithData:self encoding:NSASCIIStringEncoding]
                stringByReplacingOccurrencesOfString:@"\r\n" withString:@"␍␊⏎"]
                stringByReplacingOccurrencesOfString:@"\r" withString:@"␍⏎"]
               stringByReplacingOccurrencesOfString:@"\n" withString:@"␊⏎"]
              stringByReplacingOccurrencesOfString:@"\t" withString:@"␉"]
             stringByReplacingOccurrencesOfString:@"⏎" withString:@"\n"];
    

}
@end

NS_ASSUME_NONNULL_END

