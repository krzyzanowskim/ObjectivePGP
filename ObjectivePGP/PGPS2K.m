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

#import "PGPLogging.h"
#import "PGPMacros+Private.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>

#import "NSData+PGPUtils.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPCryptoHash.h"
#import "PGPCryptoUtils.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

static const unsigned int PGP_SALT_SIZE = 8;
static const unsigned int PGP_DEFAULT_ITERATIONS_COUNT = 215;

@interface PGPS2K ()

@property (nonatomic, copy, readwrite) NSData *salt;

@end

@implementation PGPS2K

- (instancetype)initWithSpecifier:(PGPS2KSpecifier)specifier hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm {
    if ((self = [super init])) {
        _specifier = specifier;
        _hashAlgorithm = hashAlgorithm;
        _salt = [PGPCryptoUtils randomData:PGP_SALT_SIZE];
        _iterationsCount = PGP_DEFAULT_ITERATIONS_COUNT;
    }
    return self;
}

+ (PGPS2K *)S2KFromData:(NSData *)data atPosition:(NSUInteger)position length:(nullable NSUInteger *)length {
    PGPAssertClass(data, NSData);

    PGPS2K *s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSimple hashAlgorithm:PGPHashSHA1]; // just default values, overriden in next line
    NSUInteger positionAfter = [s2k parseS2K:data atPosition:position];
    if (length) {
        *length = MAX(positionAfter - position, (NSUInteger)0);
    }
    return s2k;
}

- (NSUInteger)parseS2K:(NSData *)data atPosition:(NSUInteger)startingPosition {
    // S2K

    // string-to-key specifier is being given
    NSUInteger position = startingPosition;
    [data getBytes:&_specifier range:(NSRange){position, 1}];
    position = position + 1;

    NSAssert(_specifier == PGPS2KSpecifierIteratedAndSalted || _specifier == PGPS2KSpecifierSalted || _specifier == PGPS2KSpecifierSimple || _specifier == PGPS2KSpecifierGnuDummy, @"Bad s2k specifier");

    // this is not documented, but now I need to read S2K key specified by s2kSpecifier
    // 3.7.1.1.  Simple S2K

    // Octet  1:        hash algorithm
    [data getBytes:&_hashAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    // Octets 2-9:      8-octet salt value
    if (self.specifier == PGPS2KSpecifierSalted || self.specifier == PGPS2KSpecifierIteratedAndSalted) {
        // read salt 8 bytes
        self.salt = [data subdataWithRange:(NSRange){position, PGP_SALT_SIZE}];
        position = position + self.salt.length;
    }

    // Octet  10:       count, a one-octet, coded value
    if (_specifier == PGPS2KSpecifierIteratedAndSalted) {
        [data getBytes:&self->_iterationsCount range:(NSRange){position, 1}];
        position = position + 1;
    }

    if (self.specifier == PGPS2KSpecifierGnuDummy) {
        // read 3 bytes, and check if it's "GNU" followed by 0x01 || 0x02
        let gnuMarkerSize = 4;
        let gnuString = [[NSString alloc] initWithData:[data subdataWithRange:(NSRange){position, gnuMarkerSize - 1}] encoding:NSASCIIStringEncoding];
        if (PGPEqualObjects(gnuString,@"GNU")) {
            position = position + gnuMarkerSize;
        } else {
            PGPLogWarning(@"Unknown S2K");
        }
    }

    return position;
}

- (UInt32)codedIterationsCount {
    if (self.iterationsCount > 65011712) {
        return 255;
    }

    return ((UInt32)16 + (self.iterationsCount & 15)) << ((self.iterationsCount >> 4) + 6);
}

- (nullable NSData *)export:(NSError *__autoreleasing *)error {
    NSMutableData *data = [NSMutableData data];
    [data appendBytes:&_specifier length:1];
    [data appendBytes:&_hashAlgorithm length:1];

    if (self.specifier == PGPS2KSpecifierSalted || self.specifier == PGPS2KSpecifierIteratedAndSalted) {
        [data appendData:self.salt];
    }

    if (self.specifier == PGPS2KSpecifierIteratedAndSalted) {
        if (self.iterationsCount == 0) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unexpected count: 0" }];
            }
            return nil;
        }

        [data appendBytes:&self->_iterationsCount length:1];
    }

    return data;
}

- (nullable NSData *)buildKeyDataForPassphrase:(NSData *)passphrase prefix:(nullable NSData *)prefix salt:(NSData *)salt codedCount:(UInt32)codedCount {
    PGPUpdateBlock updateBlock = nil;
    switch (self.specifier) {
        case PGPS2KSpecifierGnuDummy:
            // no secret key
            break;
        case PGPS2KSpecifierSimple: {
            let data = [NSMutableData dataWithData:prefix ?: [NSData data]];
            [data pgp_appendData:passphrase];

            // passphrase
            updateBlock = ^(PGP_NOESCAPE void (^update)(const void *data, int length)) {
                update(data.bytes, (int)data.length);
            };
        } break;
        case PGPS2KSpecifierSalted: {
            // salt + passphrase
            // This includes a "salt" value in the S2K specifier -- some arbitrary
            // data -- that gets hashed along with the passphrase string, to help
            // prevent dictionary attacks.
            let data = [NSMutableData dataWithData:prefix ?: [NSData data]];
            [data appendData:salt];
            [data pgp_appendData:passphrase];

            updateBlock = ^(PGP_NOESCAPE void (^update)(const void *data, int length)) {
                update(data.bytes, (int)data.length);
            };
        } break;
        case PGPS2KSpecifierIteratedAndSalted: {
            // iterated (salt + passphrase)
            let data = [NSMutableData dataWithData:salt];
            [data pgp_appendData:passphrase];

            updateBlock = ^(PGP_NOESCAPE void (^update)(const void *data, int length)) {
                // prefix first
                update(prefix.bytes, (int)prefix.length);

                // then iterate
                int iterations = 0;
                while (iterations * data.length < codedCount) {
                    let nextTotalLength = (iterations + 1) * data.length;
                    if (nextTotalLength > codedCount) {
                        let totalLength = iterations * data.length;
                        let remainder = [data subdataWithRange:(NSRange){0, codedCount - totalLength}];
                        update(remainder.bytes, (int)remainder.length);
                    } else {
                        update(data.bytes, (int)data.length);
                    }
                    iterations++;
                }
            };
        } break;
        default:
            // unknown or unsupported
            break;
    }

    if (updateBlock) {
        return PGPCalculateHash(self.hashAlgorithm, updateBlock);
    }

    return nil;
}

/**
 *  Calculate key for given passphrase
 *  An S2K specifier can be stored in the secret keyring to specify how
 *  to convert the passphrase to a key that unlocks the secret data.
 *  Simple S2K hashes the passphrase to produce the session key.
 *
 *  @param passphrase Passphrase
 *  @param symmetricAlgorithm    Cipher algorithm
 *
 *  @return NSData with key
 */
- (nullable NSData *)produceSessionKeyWithPassphrase:(NSString *)passphrase symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm {
    PGPAssertClass(passphrase, NSString);

    let passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
    var hashData = [self buildKeyDataForPassphrase:passphraseData prefix:nil salt:self.salt codedCount:self.codedIterationsCount];
    if (!hashData) {
        return nil;
    }

    // Keysize
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:symmetricAlgorithm];
    NSAssert(keySize <= 32, @"invalid keySize");

    /*
     If the hash size is less than the key size, multiple instances of the
     hash context are created -- enough to produce the required key data.
     These instances are preloaded with 0, 1, 2, ... octets of zeros (that
     is to say, the first instance has no preloading, the second gets
     preloaded with 1 octet of zero, the third is preloaded with two
     octets of zeros, and so forth).
     */
    if (hashData.length < keySize) {
        var level = 1;
        Byte zero = 0;
        let prefix = [NSMutableData data];
        let expandedHashData = [NSMutableData dataWithData:hashData];
        while (expandedHashData.length < keySize) {
            for (int i = 0; i < level; i++) {
                [prefix appendBytes:&zero length:1];
            }

            let prefixedHashData = [self buildKeyDataForPassphrase:passphraseData prefix:prefix salt:self.salt codedCount:self.codedIterationsCount];
            [expandedHashData appendData:prefixedHashData];

            level++;
        }
        hashData = expandedHashData;
    }

    // the high-order (leftmost) octets of the hash are used as the key.
    return [hashData subdataWithRange:(NSRange){0, MIN(hashData.length, keySize)}];
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let copy = PGPCast([[self.class allocWithZone:zone] initWithSpecifier:self.specifier hashAlgorithm:self.hashAlgorithm], PGPS2K);
    copy.salt = [self.salt copyWithZone:zone];
    copy.iterationsCount = self.iterationsCount;
    return copy;
}

@end

NS_ASSUME_NONNULL_END
