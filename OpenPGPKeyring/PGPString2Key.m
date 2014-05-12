//
//  PGPS2K.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPString2Key.h"
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>

#import "PGPCryptoUtils.h"

static const unsigned int PGP_SALT_SIZE = 8;

@implementation PGPString2Key

+ (PGPString2Key *) string2KeyFromData:(NSData *)data atPosition:(NSUInteger)position
{
    PGPString2Key *s2k = [[PGPString2Key alloc] init];
    NSUInteger positionAfter = [s2k parseS2K:data atPosition:position];
    s2k.length = (positionAfter - position);
    return s2k;
}


- (NSUInteger) parseS2K:(NSData *)data atPosition:(NSUInteger)position
{
    // S2K

    // string-to-key specifier is being given
    [data getBytes:&_specifier range:(NSRange) {position, 1}];
    position = position + 1;

    NSAssert(_specifier == PGPS2KSpecifierIteratedAndSalted || _specifier == PGPS2KSpecifierSalted || _specifier == PGPS2KSpecifierSimple, @"Bad s2k specifier");

    // this is not documented, but now I need to read S2K key specified by s2kSpecifier
    // 3.7.1.1.  Simple S2K

    // Octet  1:        hash algorithm
    [data getBytes:&_algorithm range:(NSRange) {position,1}];
    position = position + 1;

    // Octets 2-9:      8-octet salt value
    if (_specifier != PGPS2KSpecifierSimple) {
        // read salt 8 bytes
        _salt = [data subdataWithRange:(NSRange) {position, PGP_SALT_SIZE}];
        position = position + _salt.length;
    }

    // Octet  10:       count, a one-octet, coded value
    if (_specifier == PGPS2KSpecifierIteratedAndSalted) {
        UInt32 c = 0;
        [data getBytes:&c range:(NSRange) {position, 1}];
        _count = ((UInt32)16 + (c & 15)) << ((c >> 4) + 6); //FIXME: what is wrong with that ?
        //_count = CFSwapInt32BigToHost(_count);
        position = position + 1;
    }

    return position;
}

//TODO: only SHA1 is implemented, implement digest from self.algorithm
// http://stackoverflow.com/questions/3468268/objective-c-sha1
- (NSData *) produceKeyWithPassphrase:(NSString *)passphrase keySize:(NSUInteger)keySize
{
    NSMutableData *result = [NSMutableData data];
    NSData *passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:self.algorithm]; // SHA hash size

    switch (self.specifier) {
        case PGPS2KSpecifierSimple:
        {
            // passphrase
            CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
            if (ctx) {
                CC_SHA1_Init(ctx);
                CC_SHA1_Update(ctx, passphraseData.bytes, passphrase.length);
                UInt8 *digest = calloc(hashSize, sizeof(UInt8));
                if (digest) {
                    CC_SHA1_Final(digest, ctx);
                    [result appendBytes:digest length:hashSize];
                    free(digest);
                }
                free(ctx);
            }
        }
            break;
        case PGPS2KSpecifierSalted:
        {
            // salt + passphrase
            // This includes a "salt" value in the S2K specifier -- some arbitrary
            // data -- that gets hashed along with the passphrase string, to help
            // prevent dictionary attacks.

            CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
            if (ctx) {
                CC_SHA1_Init(ctx);
                CC_SHA1_Update(ctx, self.salt.bytes, self.salt.length);
                CC_SHA1_Update(ctx, passphraseData.bytes, passphrase.length);
                UInt8 *digest = calloc(hashSize, sizeof(UInt8));
                if (digest) {
                    CC_SHA1_Final(digest, ctx);
                    [result appendBytes:digest length:hashSize];
                    free(digest);
                }
                free(ctx);
            }
        }
            break;
        case PGPS2KSpecifierIteratedAndSalted:
        {
            // iterated (salt + passphrase)

            NSPointerArray *ctxArray = [NSPointerArray pointerArrayWithOptions:NSPointerFunctionsOpaqueMemory];
            for (NSUInteger n = 0; n * hashSize < keySize; ++n) {
                CC_SHA1_CTX *ctx = calloc(1, sizeof(CC_SHA1_CTX));
                if (ctx) {
                    CC_SHA1_Init(ctx);
                    [ctxArray addPointer:ctx];
                }
            }

            // append
            for (NSUInteger n = 0; n < ctxArray.count ; ++n) {
                CC_SHA1_CTX *ctx = [ctxArray pointerAtIndex:n];
                for (NSUInteger i = 0; i < self.count; i += self.salt.length + passphraseData.length) {
                    NSUInteger j = self.salt.length + passphraseData.length;
                    if (i + j > self.count && i != 0) {
                        j = self.count - i;
                    }
                    // add salt
                    CC_SHA1_Update(ctx, self.salt.bytes, j > self.salt.length ? self.salt.length : j);
                    // add passphrase
                    if (j > self.salt.length) {
                        CC_SHA1_Update(ctx, passphraseData.bytes, j - self.salt.length);
                    }
                }
            }

            // finalize
            while (ctxArray.count > 0) {
                CC_SHA1_CTX *ctx = [ctxArray pointerAtIndex:0];
                UInt8 *digest = calloc(hashSize, sizeof(UInt8));
                if (digest) {
                    CC_SHA1_Final(digest, ctx);
                    [result appendBytes:digest length:hashSize];
                    free(digest);
                }
                [ctxArray removePointerAtIndex:0];
                free(ctx);
            }


        }
            break;
        default:
            break;
    }
    return [result copy];
}


@end
