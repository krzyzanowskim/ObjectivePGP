//
//  PGPS2K.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPString2Key.h"

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
        UInt8 c = 0;
        [data getBytes:&c range:(NSRange) {position, 1}];
        _count = ((UInt32)16 + ((UInt32)c & 15)) << (((UInt32)c >> 4) + 6); //FIXME: what is wrong with that ?
        position = position + 1;
    }

    return position;
}

- (void)dealloc
{
}

@end
