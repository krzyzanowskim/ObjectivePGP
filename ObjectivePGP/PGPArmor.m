//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPArmor.h"
#import "NSData+PGPUtils.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPArmor

+ (BOOL)isArmoredData:(NSData *)data {
    PGPAssertClass(data, NSData);

    // detect if armored, check for string -----BEGIN PGP
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (str && [str hasPrefix:@"-----BEGIN PGP"]) {
        return YES;
    }
    return NO;
}

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type {
    return [[self class] armored:data as:type part:NSUIntegerMax of:NSUIntegerMax];
}

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type part:(NSUInteger)part of:(NSUInteger)ofParts {
    NSMutableDictionary *headers = [@{ @"Version": @"ObjectivePGP", @"Comment": @"https://www.objectivepgp.com", @"Charset": @"UTF-8" } mutableCopy];

    NSMutableString *headerString = [NSMutableString stringWithString:@"-----"];
    NSMutableString *footerString = [NSMutableString stringWithString:@"-----"];
    switch (type) {
        case PGPArmorTypePublicKey:
            [headerString appendString:@"BEGIN PGP PUBLIC KEY BLOCK"];
            [footerString appendString:@"END PGP PUBLIC KEY BLOCK"];
            break;
        case PGPArmorTypeSecretKey:
            [headerString appendString:@"BEGIN PGP PRIVATE KEY BLOCK"];
            [footerString appendString:@"END PGP PRIVATE KEY BLOCK"];
            break;
        case PGPArmorTypeSignature:
            [headerString appendString:@"BEGIN PGP SIGNATURE"];
            [footerString appendString:@"END PGP SIGNATURE"];
            break;
        case PGPArmorTypeMessage:
            [headerString appendString:@"BEGIN PGP MESSAGE"];
            [footerString appendString:@"END PGP MESSAGE"];
            break;
        case PGPArmorTypeMultipartMessagePartX:
            [headerString appendFormat:@"BEGIN PGP MESSAGE, PART %@", @(part)];
            [footerString appendFormat:@"END PGP MESSAGE, PART %@", @(part)];
            break;
        case PGPArmorTypeMultipartMessagePartXOfY:
            [headerString appendFormat:@"BEGIN PGP MESSAGE, PART %@/%@", @(part), @(ofParts)];
            [footerString appendFormat:@"END PGP MESSAGE, PART %@/%@", @(part), @(ofParts)];
            break;
        default:
            NSAssert(true, @"Message type not supported");
            break;
    }

    [headerString appendString:@"-----\n"];
    [footerString appendString:@"-----\n"];

    NSMutableString *armoredMessage = [NSMutableString string];
    // - An Armor Header Line, appropriate for the type of data
    [armoredMessage appendString:headerString];

    // - Armor Headers
    for (NSString *key in headers.allKeys) {
        [armoredMessage appendFormat:@"%@: %@\n", key, headers[key]];
    }

    // - A blank (zero-length, or containing only whitespace) line
    [armoredMessage appendString:@"\n"];

    // - The ASCII-Armored data
    NSString *radix64 = [data base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength | NSDataBase64EncodingEndLineWithLineFeed];
    [armoredMessage appendString:radix64];
    [armoredMessage appendString:@"\n"];

    // - An Armor Checksum
    UInt32 checksum = [data pgp_CRC24];
    UInt8 c[3]; // 24 bit
    c[0] = (UInt8)(checksum >> 16);
    c[1] = (UInt8)(checksum >> 8);
    c[2] = (UInt8)checksum;

    NSData *checksumData = [NSData dataWithBytes:&c length:sizeof(c)];
    [armoredMessage appendString:@"="];
    [armoredMessage appendString:[checksumData base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength | NSDataBase64EncodingEndLineWithLineFeed]];
    [armoredMessage appendString:@"\n"];

    // - The Armor Tail, which depends on the Armor Header Line
    [armoredMessage appendString:footerString];
    return armoredMessage;
};

+ (nullable NSData *)readArmored:(NSString *)string error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(string, NSString);

    NSScanner *scanner = [[NSScanner alloc] initWithString:string];
    scanner.charactersToBeSkipped = nil;

    // check header line
    NSString *headerLine = nil;
    [scanner scanUpToCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:&headerLine];
    if (!PGPEqualObjects(headerLine, @"-----BEGIN PGP MESSAGE-----") && !PGPEqualObjects(headerLine, @"-----BEGIN PGP PUBLIC KEY BLOCK-----") && !PGPEqualObjects(headerLine, @"-----BEGIN PGP PRIVATE KEY BLOCK-----") && !PGPEqualObjects(headerLine, @"-----BEGIN PGP SECRET KEY BLOCK-----") && // PGP 2.x generates the header "BEGIN PGP SECRET KEY BLOCK" instead of "BEGIN PGP PRIVATE KEY BLOCK"
        !PGPEqualObjects(headerLine, @"-----BEGIN PGP SIGNATURE-----") && ![headerLine hasPrefix:@"-----BEGIN PGP MESSAGE, PART"]) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Invalid header" }];
        }
        return nil;
    }

    // consume newline
    [scanner scanString:@"\r" intoString:nil];
    [scanner scanString:@"\n" intoString:nil];

    NSString *line = nil;

    if (![scanner scanCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:nil]) {
        // Scan headers (Optional)
        [scanner scanUpToCharactersFromSet:[[NSCharacterSet newlineCharacterSet] invertedSet] intoString:nil];

        while ([scanner scanCharactersFromSet:[[NSCharacterSet newlineCharacterSet] invertedSet] intoString:&line]) {
            // consume newline
            [scanner scanString:@"\r" intoString:nil];
            [scanner scanString:@"\n" intoString:nil];
        }
    }

    // skip blank line
    [scanner scanCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:nil];

    // read base64 data
    BOOL base64Section = YES;
    NSMutableString *base64String = [NSMutableString string];
    while (base64Section && [scanner scanCharactersFromSet:[[NSCharacterSet newlineCharacterSet] invertedSet] intoString:&line]) {
        // consume newline
        [scanner scanString:@"\r" intoString:nil];
        [scanner scanString:@"\n" intoString:nil];

        if ([line hasPrefix:@"="]) {
            scanner.scanLocation = scanner.scanLocation - (line.length + 2);
            base64Section = NO;
        } else {
            [base64String appendFormat:@"%@\n", line];
        }
    }

    // read checksum
    NSString *checksumString = nil;
    [scanner scanUpToCharactersFromSet:[[NSCharacterSet newlineCharacterSet] invertedSet] intoString:&line];
    // consume newline
    [scanner scanString:@"\r" intoString:nil];
    [scanner scanString:@"\n" intoString:nil];

    if ([scanner scanString:@"=" intoString:nil]) {
        [scanner scanUpToCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:&checksumString];
        // consume newline
        [scanner scanString:@"\r" intoString:nil];
        [scanner scanString:@"\n" intoString:nil];
    }

    if (!checksumString) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Missing checksum" }];
        }
        return nil;
    }

    // read footer
    BOOL footerMatchHeader = NO;
    [scanner scanUpToCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:&line];
    // consume newline
    [scanner scanString:@"\r" intoString:nil];
    [scanner scanString:@"\n" intoString:nil];

    if ([line hasSuffix:[headerLine substringFromIndex:12]]) {
        footerMatchHeader = YES;
    }

    if (!footerMatchHeader) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Footer don't match to header" }];
        }
        return nil;
    }

    // binary data from base64 part
    NSData *binaryData = [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];

    // validate checksum
    NSData *readChecksumData = [[NSData alloc] initWithBase64EncodedString:checksumString options:NSDataBase64DecodingIgnoreUnknownCharacters];

    UInt32 calculatedCRC24 = [binaryData pgp_CRC24];
    calculatedCRC24 = CFSwapInt32HostToBig(calculatedCRC24);
    calculatedCRC24 = calculatedCRC24 >> 8;
    NSData *calculatedCRC24Data = [NSData dataWithBytes:&calculatedCRC24 length:3];
    if (!PGPEqualObjects(calculatedCRC24Data,readChecksumData)) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Checksum mismatch" }];
        }
        return nil;
    }

    return binaryData;
}

@end

NS_ASSUME_NONNULL_END
