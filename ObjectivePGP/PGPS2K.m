//
//  PGPS2K.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPS2K.h"
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>

#import "PGPCryptoUtils.h"
#import "NSData+PGPUtils.h"

static const unsigned int PGP_SALT_SIZE = 8;

@implementation PGPS2K

+ (PGPS2K *) string2KeyFromData:(NSData *)data atPosition:(NSUInteger)position
{
    PGPS2K *s2k = [[PGPS2K alloc] init];
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
    NSMutableData *toHashData = [NSMutableData data];
    NSData *passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:self.algorithm]; // SHA hash size

    switch (self.specifier) {
        case PGPS2KSpecifierSimple:
        {
            // passphrase
            [toHashData appendData:passphraseData];
        }
            break;
        case PGPS2KSpecifierSalted:
        {
            // salt + passphrase
            // This includes a "salt" value in the S2K specifier -- some arbitrary
            // data -- that gets hashed along with the passphrase string, to help
            // prevent dictionary attacks.

            [toHashData appendData:self.salt];
            [toHashData appendData:passphraseData];
        }
            break;
        case PGPS2KSpecifierIteratedAndSalted:
        {
            // iterated (salt + passphrase)
            @autoreleasepool {
                // memory overhead with subdataWithRange is significant, this is why it's not used here
                for (NSUInteger n = 0; n * hashSize < keySize; ++n)
                {
                    for (NSUInteger i = 0; i < self.count; i += self.salt.length + passphraseData.length)
                    {
                        NSUInteger j = self.salt.length + passphraseData.length;
                        if (i + j > self.count && i != 0) {
                            j = self.count - i;
                        }

                        // add salt
                        NSUInteger saltlen = j > self.salt.length ? self.salt.length : j;
                        UInt8 *saltbytes = calloc(saltlen, sizeof(UInt8));
                        [self.salt getBytes:saltbytes range:(NSRange){0,saltlen}];
                        [toHashData appendBytes:saltbytes length:saltlen];
                        free(saltbytes);
                        // add passphrase
                        if (j > self.salt.length) {
                            NSUInteger passlen = j - self.salt.length;
                            UInt8 *passbytes = calloc(passlen, sizeof(UInt8));
                            [passphraseData getBytes:passbytes range:(NSRange){0,passlen}];
                            [toHashData appendBytes:passbytes length:passlen];
                            free(passbytes);
                        }
                    }
                }
                NSLog(@"memory test");
            }
        }
            break;
        default:
            break;
    }

    switch (self.algorithm) {
        case PGPHashMD5:
            [result appendData:[toHashData pgpMD5]];
            break;
        case PGPHashSHA1:
            [result appendData:[toHashData pgpSHA1]];
            break;
        case PGPHashSHA224:
            [result appendData:[toHashData pgpSHA224]];
            break;
        case PGPHashSHA256:
            [result appendData:[toHashData pgpSHA256]];
            break;
        case PGPHashSHA384:
            [result appendData:[toHashData pgpSHA384]];
            break;
        case PGPHashSHA512:
            [result appendData:[toHashData pgpSHA512]];
            break;
        case PGPHashRIPEMD160:
            [result appendData:[toHashData pgpRIPEMD160]];
        default:
            NSAssert(YES, @"Hash algorithm not supported");
            break;
    }

    return [result copy];
}


@end
