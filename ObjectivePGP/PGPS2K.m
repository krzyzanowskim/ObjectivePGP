//
//  PGPS2K.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A string to key (S2K) specifier encodes a mechanism for producing a key to be used with a symmetric block cipher from a string of octets.
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

- (NSData *)salt
{
    if (!_salt) {
        NSMutableData *s = [NSMutableData data];
        for (int i = 0; i < 8; i++) {
            Byte b = arc4random_uniform(255);
            [s appendBytes:&b length:sizeof(b)];
        }
        _salt = [s copy];
    }
    return _salt;
}

- (NSUInteger) parseS2K:(NSData *)data atPosition:(NSUInteger)startingPosition
{
    // S2K

    // string-to-key specifier is being given
    NSUInteger position = startingPosition;
    [data getBytes:&_specifier range:(NSRange) {position, 1}];
    position = position + 1;

    NSAssert(_specifier == PGPS2KSpecifierIteratedAndSalted || _specifier == PGPS2KSpecifierSalted || _specifier == PGPS2KSpecifierSimple, @"Bad s2k specifier");

    // this is not documented, but now I need to read S2K key specified by s2kSpecifier
    // 3.7.1.1.  Simple S2K

    // Octet  1:        hash algorithm
    [data getBytes:&_hashAlgorithm range:(NSRange) {position,1}];
    position = position + 1;

    // Octets 2-9:      8-octet salt value
    if (_specifier != PGPS2KSpecifierSimple) {
        // read salt 8 bytes
        _salt = [data subdataWithRange:(NSRange) {position, PGP_SALT_SIZE}];
        position = position + _salt.length;
    }

    // Octet  10:       count, a one-octet, coded value
    if (_specifier == PGPS2KSpecifierIteratedAndSalted) {
        [data getBytes:&_uncodedCount range:(NSRange) {position, 1}];
        position = position + 1;
    }

    return position;
}

- (UInt32) codedCount
{
    UInt32 expbias = 6;
    return ((UInt32)16 + (_uncodedCount & 15)) << ((_uncodedCount >> 4) + expbias);
}

- (NSData *) export:(NSError *__autoreleasing*)error
{
    NSMutableData *data = [NSMutableData data];
    [data appendBytes:&_specifier length:1];
    [data appendBytes:&_hashAlgorithm length:1];

    if (_specifier != PGPS2KSpecifierSimple) {
        [data appendData:self.salt];
    }

    if (_specifier == PGPS2KSpecifierIteratedAndSalted) {
        NSAssert(self.uncodedCount != 0, @"Count value is 0");
        if (self.uncodedCount == 0) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unexpected count is 0"}];
            }
            return nil;
        }

        [data appendBytes:&_uncodedCount length:1];
    }

    return [data copy];
}


/**
 *  Calculate key for given password
 *  An S2K specifier can be stored in the secret keyring to specify how
 *  to convert the passphrase to a key that unlocks the secret data.
 *  Simple S2K hashes the passphrase to produce the session key.
 *
 *  @param passphrase Password
 *  @param keySize    Packet key size
 *
 *  @return NSData with key
 */
- (NSData *) produceSessionKeyWithPassphrase:(NSString *)passphrase keySize:(NSUInteger)keySize
{
    NSMutableData *result = [NSMutableData data];
    NSMutableData *toHashData = [NSMutableData data];
    NSData *passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger hashSize = [PGPCryptoUtils hashSizeOfHashAlhorithm:self.hashAlgorithm]; // SHA hash size

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
                    for (NSUInteger i = 0; i < self.codedCount; i += self.salt.length + passphraseData.length)
                    {
                        NSUInteger j = self.salt.length + passphraseData.length;
                        if (i + j > self.codedCount && i != 0) {
                            j = self.codedCount - i;
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
            }
        }
            break;
        default:
            break;
    }

    NSData *hash = [toHashData pgp_HashedWithAlgorithm:self.hashAlgorithm];
    [result appendData:hash];

    return [result copy];
}


@end
