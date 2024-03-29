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

#import "PGPDataScanner.h"

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
    NSMutableDictionary *headers = [@{ @"Version": @"ObjectivePGP", @"Comment": @"https://objectivepgp.com", @"Charset": @"UTF-8" } mutableCopy];

    let headerString = [NSMutableString string];
    let footerString = [NSMutableString string];
    switch (type) {
        case PGPArmorPublicKey:
            [headerString appendString:@"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"];
            [footerString appendString:@"-----END PGP PUBLIC KEY BLOCK-----\n"];
            break;
        case PGPArmorSecretKey:
            [headerString appendString:@"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"];
            [footerString appendString:@"-----END PGP PRIVATE KEY BLOCK-----\n"];
            break;
        case PGPArmorSignature:
            [headerString appendString:@"-----BEGIN PGP SIGNATURE-----\n"];
            [footerString appendString:@"-----END PGP SIGNATURE-----\n"];
            break;
        case PGPArmorMessage:
            [headerString appendString:@"-----BEGIN PGP MESSAGE-----\n"];
            [footerString appendString:@"-----END PGP MESSAGE-----\n"];
            break;
        case PGPArmorMultipartMessagePartX:
            [headerString appendFormat:@"-----BEGIN PGP MESSAGE, PART %@-----\n", @(part)];
            [footerString appendFormat:@"-----END PGP MESSAGE, PART %@-----\n", @(part)];
            break;
        case PGPArmorMultipartMessagePartXOfY:
            [headerString appendFormat:@"-----BEGIN PGP MESSAGE, PART %@/%@-----\n", @(part), @(ofParts)];
            [footerString appendFormat:@"-----END PGP MESSAGE, PART %@/%@-----\n", @(part), @(ofParts)];
            break;
        default:
            NSAssert(true, @"Message type not supported");
            return @"";
    }

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

+ (nullable NSData *)readArmoredData:(NSData*)data error:(NSError * __autoreleasing _Nullable *)error {
    let scanner = [[PGPDataScanner alloc] initWithData:data];
    let crlf = [NSData dataWithBytes:"\r\n" length:2];
    let cr = [NSData dataWithBytes:"\r" length:1];
    let lf = [NSData dataWithBytes:"\n" length:1];

    let headerDelimiter = [@"-----" dataUsingEncoding:NSASCIIStringEncoding];
    
    if (![scanner scanData:headerDelimiter intoData:nil]){
        // error should have opening header delimeter
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Armoured data must begin with header" }];
        }
        return nil;
    }
    NSData * beginData;
    if (![scanner scanUpToData:headerDelimiter intoData:&beginData]){
        // error expecting BEGIN
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        return nil;
    }
    NSString* header = [NSString.alloc initWithData:beginData encoding:NSASCIIStringEncoding];
    NSRange armorKindRange = [header rangeOfString:@"BEGIN " options:NSAnchoredSearch range:NSMakeRange(0,header.length)];
    NSString * armorKind = [header substringFromIndex:NSMaxRange(armorKindRange)];
    // test armorKind here
    if (![armorKind hasPrefix:@"PGP "] &&
        !PGPEqualObjects(armorKind, @"PGP MESSAGE") &&
        !PGPEqualObjects(armorKind, @"PGP PUBLIC KEY BLOCK") &&
        !PGPEqualObjects(armorKind, @"PGP PRIVATE KEY BLOCK") &&
        !PGPEqualObjects(armorKind, @"PGP SECRET KEY BLOCK") && // PGP 2.x generates the header "BEGIN PGP SECRET KEY BLOCK" instead of "BEGIN PGP PRIVATE KEY BLOCK"
        !PGPEqualObjects(armorKind, @"PGP SIGNATURE") &&
        ![armorKind hasPrefix:@"PGP MESSAGE, PART"])
    {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Invalid armor header" }];
        }
        return nil;
    }
    
    if (![scanner scanData:headerDelimiter intoData:nil]){
        // error should have closing header delimeter
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        return nil;
    }
    // determine linebreakData from first line
    NSData * lineBreak = nil;
    if ([scanner scanData:crlf intoData:nil]) lineBreak = crlf;
    else if ([scanner scanData:cr intoData:nil]) lineBreak = cr;
    else if ([scanner scanData:lf intoData:nil]) lineBreak = lf;
    else {
        // not crlf, or cr or lf
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        return nil;
    }
    
    
    NSMutableData * tail = [lineBreak mutableCopy];
    [tail appendData:headerDelimiter];
    [tail appendData:[[@"END " stringByAppendingString:armorKind] dataUsingEncoding:NSASCIIStringEncoding]];
    [tail appendData:headerDelimiter];
    
    // scann comments
    while ([scanner scanUpToData:lineBreak intoData:nil]) {
        if (![scanner scanData:lineBreak intoData:nil]){
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
            }
            return nil;
        }
    }
    // consume empty line after comments;
    if (![scanner scanData:lineBreak intoData:nil]){
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        return nil;
    }
    
    NSData * armorBody;
    if (![scanner scanUpToData:tail intoData:&armorBody] || ![scanner scanData:tail intoData:nil]){
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Tail doesn't match armor header" }];
        }
    }
    if (![scanner isAtEnd]){
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unexpected data after armor tail" }];
        }
    }
    
    //see if the last line of data is the optional checksum
    NSMutableData * checkSumDelimiter = [lineBreak mutableCopy];
    [checkSumDelimiter appendData: [NSData dataWithBytes:"=" length:1]];
    let delimChecksumLength = checkSumDelimiter.length+4;  //   <break>=<4char>
    NSData * checksum = nil;
    if (armorBody.length > delimChecksumLength){
        if ([[armorBody subdataWithRange:NSMakeRange(armorBody.length-delimChecksumLength, checkSumDelimiter.length)] isEqualToData:checkSumDelimiter]){
            let checksumData = [armorBody subdataWithRange:NSMakeRange(armorBody.length-4,4)];
            checksum = [[NSData alloc] initWithBase64EncodedData:(NSData*)checksumData options:NSDataBase64DecodingIgnoreUnknownCharacters];
            armorBody = [armorBody subdataWithRange:NSMakeRange(0, armorBody.length-delimChecksumLength)];
        }
    }
    
    let binaryData = [[NSData alloc] initWithBase64EncodedData:armorBody options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    if (checksum){
        UInt32 calculatedCRC24 = [binaryData pgp_CRC24];
        calculatedCRC24 = CFSwapInt32HostToBig(calculatedCRC24);
        calculatedCRC24 = calculatedCRC24 >> 8;
        let calculatedCRC24Data = [NSData dataWithBytes:&calculatedCRC24 length:3];
        if (!PGPEqualObjects(calculatedCRC24Data, checksum)) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"PGP Armor Checksum mismatch" }];
            }
            return nil;
        }
    }
    return binaryData;
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
        
        NSError *armorError = nil;
        let extractedData = [[NSMutableArray<NSData *> alloc] init];
        for (NSString *extractedString in extractedBlocks) {
            @autoreleasepool {
                NSError *internalArmorError = nil;
                let armoredData = [PGPArmor readArmored:extractedString error:&internalArmorError];
                if (!armoredData || internalArmorError) {
                    if (error) {
                        armorError = [internalArmorError copy];
                    }
                    break;
                }
                
                [extractedData pgp_addObject:armoredData];
            }
        }
        if (armorError) {
            * error = armorError;
            return nil;
        }
        return extractedData;
    }
    return @[binRingData];
}

@end

NS_ASSUME_NONNULL_END
