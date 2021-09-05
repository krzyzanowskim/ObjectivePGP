//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPArmor.h"
#import "PGPPacket.h"

#import "NSData+PGPUtils.h"
#import "NSArray+PGPUtils.h"

#import "PGPFoundation.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPArmor

+ (BOOL)isArmoredData:(NSData *)data {
    PGPAssertClass(data, NSData);

    // detect if armored, check for string -----BEGIN PGP
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!str) {
        return NO;
    }
    NSString *stringValue;
    let scanner = [NSScanner scannerWithString:str];
    scanner.charactersToBeSkipped = nil;
    if ([scanner scanUpToString:@"-----BEGIN PGP" intoString:&stringValue] && scanner.atEnd) {
        return NO;
    }
    return YES;
}

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type {
    return [[self class] armored:data as:type part:NSUIntegerMax of:NSUIntegerMax];
}

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type part:(NSUInteger)part of:(NSUInteger)ofParts {
    NSMutableDictionary *headers = [@{ @"Version": @"ObjectivePGP", @"Comment": @"https://www.objectivepgp.com", @"Charset": @"UTF-8" } mutableCopy];

    NSMutableString *headerString = [NSMutableString stringWithString:@"-----"];
    NSMutableString *footerString = [NSMutableString stringWithString:@"-----"];
    switch (type) {
        case PGPArmorPublicKey:
            [headerString appendString:@"BEGIN PGP PUBLIC KEY BLOCK"];
            [footerString appendString:@"END PGP PUBLIC KEY BLOCK"];
            break;
        case PGPArmorSecretKey:
            [headerString appendString:@"BEGIN PGP PRIVATE KEY BLOCK"];
            [footerString appendString:@"END PGP PRIVATE KEY BLOCK"];
            break;
        case PGPArmorSignature:
            [headerString appendString:@"BEGIN PGP SIGNATURE"];
            [footerString appendString:@"END PGP SIGNATURE"];
            break;
        case PGPArmorMessage:
            [headerString appendString:@"BEGIN PGP MESSAGE"];
            [footerString appendString:@"END PGP MESSAGE"];
            break;
        case PGPArmorMultipartMessagePartX:
            [headerString appendFormat:@"BEGIN PGP MESSAGE, PART %@", @(part)];
            [footerString appendFormat:@"END PGP MESSAGE, PART %@", @(part)];
            break;
        case PGPArmorMultipartMessagePartXOfY:
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

/// Read Checksum and strip it from the input Base64 string
+ (nullable NSString *)readChecksum:(NSMutableString *)base64String {
    // 1. Find checksum at the last non-empty line
    NSString * _Nullable checksumString = nil;

    let lines = [base64String componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    // 2. Find checksum line
    let output = [[NSMutableString alloc] init];
    for (NSString *line in [[lines reverseObjectEnumerator] allObjects]) {
        if ([line hasPrefix:@"="]) {
            checksumString = [line substringFromIndex:1];
        } else {
            // 3. re-build base64 string without checksum line
            if ([line length] > 0) {
                [output insertString:[NSString stringWithFormat:@"%@\n", line] atIndex:0];
            }
        }
    }
    [base64String setString:output];
    return checksumString;
}

+ (nullable NSData *)readArmored:(NSString *)string error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(string, NSString);

    let scanner = [[NSScanner alloc] initWithString:string];
    scanner.charactersToBeSkipped = nil;
    
    NSCharacterSet *newlineSet = [NSCharacterSet newlineCharacterSet];
    NSCharacterSet *notNewlineSet = [[NSCharacterSet newlineCharacterSet] invertedSet];

    // check header line
    NSString *headerLine = nil;
    [scanner scanUpToCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:&headerLine];
    if (!PGPEqualObjects(headerLine, @"-----BEGIN PGP MESSAGE-----") &&
        !PGPEqualObjects(headerLine, @"-----BEGIN PGP PUBLIC KEY BLOCK-----") &&
        !PGPEqualObjects(headerLine, @"-----BEGIN PGP PRIVATE KEY BLOCK-----") &&
        !PGPEqualObjects(headerLine, @"-----BEGIN PGP SECRET KEY BLOCK-----") && // PGP 2.x generates the header "BEGIN PGP SECRET KEY BLOCK" instead of "BEGIN PGP PRIVATE KEY BLOCK"
        !PGPEqualObjects(headerLine, @"-----BEGIN PGP SIGNATURE-----") &&
        ![headerLine hasPrefix:@"-----BEGIN PGP MESSAGE, PART"])
    {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Invalid header" }];
        }
        return nil;
    }

    // consume newline
    [scanner scanString:@"\r" intoString:nil];
    [scanner scanString:@"\n" intoString:nil];

    NSString *line = nil;

    if (![scanner scanCharactersFromSet:newlineSet intoString:nil]) {
        // Scan headers (Optional)
        [scanner scanUpToCharactersFromSet:notNewlineSet intoString:nil];
        while ([scanner scanCharactersFromSet:notNewlineSet intoString:&line]) {
            // consume newline
            [scanner scanString:@"\r" intoString:nil];
            [scanner scanString:@"\n" intoString:nil];
        }
    }

    // skip blank line
    [scanner scanCharactersFromSet:newlineSet intoString:nil];
    // consume till footer
    [scanner scanUpToString:@"-----" intoString:&line];
    
    // parse checksum + base64
    let base64String = [NSMutableString stringWithString:line];
    NSString *checksumString = nil;
    @autoreleasepool {
        [base64String replaceOccurrencesOfString:@"\r\n" withString:@"\n" options:0 range:NSMakeRange(0, base64String.length)];
        checksumString = [self readChecksum:base64String];
        [base64String replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, base64String.length)];
    }

    // read footer
    BOOL footerMatchHeader = NO;
    [scanner scanUpToCharactersFromSet:newlineSet intoString:&line];
    // consume newline
    [scanner scanString:@"\r" intoString:nil];
    [scanner scanString:@"\n" intoString:nil];

    if ([line isEqualToString:[NSString stringWithFormat:@"-----END %@",[headerLine substringFromIndex:11]]]) {
        footerMatchHeader = YES;
    }

    if (!footerMatchHeader) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Footer don't match to header" }];
        }
        return nil;
    }

    // binary data from base64 part
    let binaryData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];

    // The checksum with its leading equal sign MAY appear on the first line after the base64 encoded data.
    // validate checksum
    if (checksumString) {
        let readChecksumData = [[NSData alloc] initWithBase64EncodedString:checksumString options:0];

        UInt32 calculatedCRC24 = [binaryData pgp_CRC24];
        calculatedCRC24 = CFSwapInt32HostToBig(calculatedCRC24);
        calculatedCRC24 = calculatedCRC24 >> 8;
        let calculatedCRC24Data = [NSData dataWithBytes:&calculatedCRC24 length:3];
        if (!PGPEqualObjects(calculatedCRC24Data, readChecksumData)) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Checksum mismatch" }];
            }
            return nil;
        }
    }
    return binaryData;
}

+ (nullable NSArray<NSData *> *)convertArmoredMessage2BinaryBlocksWhenNecessary:(NSData *)binOrArmorData error:(NSError * __autoreleasing _Nullable *)error {
    let binRingData = binOrArmorData;
    // detect if armored, check for string -----BEGIN PGP
    if ([PGPArmor isArmoredData:binRingData]) {
        var armoredString = [[NSMutableString alloc] initWithData:binRingData encoding:NSUTF8StringEncoding];
        [armoredString replaceOccurrencesOfString:@"\r\n" withString:@"\n" options:0 range:NSMakeRange(0, armoredString.length)];
        [armoredString replaceOccurrencesOfString:@"\n" withString:@"\r\n" options:0 range:NSMakeRange(0, armoredString.length)];

        let extractedBlocks = [[NSMutableArray<NSString *> alloc] init];
        let regex = [[NSRegularExpression alloc] initWithPattern:@"-----(BEGIN|END) (PGP)[A-Z ]*-----" options:NSRegularExpressionDotMatchesLineSeparators error:nil];
        __block NSInteger offset = 0;
        [regex enumerateMatchesInString:armoredString options:NSMatchingReportCompletion range:NSMakeRange(0, armoredString.length) usingBlock:^(NSTextCheckingResult *_Nullable result, __unused NSMatchingFlags flags, __unused BOOL *stop) {
            @autoreleasepool {
                let substring = [armoredString substringWithRange:result.range];
                if ([substring containsString:@"END"]) {
                    NSInteger endIndex = result.range.location + result.range.length;
                    [extractedBlocks addObject:[armoredString substringWithRange:NSMakeRange(offset, endIndex - offset)]];
                } else if ([substring containsString:@"BEGIN"]) {
                    offset = result.range.location;
                }
            }
        }];

        let extractedData = [[NSMutableArray<NSData *> alloc] init];
        for (NSString *extractedString in extractedBlocks) {
            @autoreleasepool {
                NSError *armorError = nil;
                let armoredData = [PGPArmor readArmored:extractedString error:&armorError];
                if (!armoredData || armorError) {
                    if (error) {
                        *error = armorError;
                    }
                    return nil;
                }
                
                [extractedData pgp_addObject:armoredData];
            }
        }
        return extractedData;
    }
    return @[binRingData];
}

@end

NS_ASSUME_NONNULL_END
