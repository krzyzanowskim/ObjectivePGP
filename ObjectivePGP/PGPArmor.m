//
//  PGPArmor.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPArmor.h"
#import "PGPPacket.h"
#import "NSData+PGPUtils.h"


@implementation PGPArmor

+ (NSData *) armoredData:(NSData *)dataToArmor as:(PGPArmorType)armorType
{
    return [[self class] armoredData:dataToArmor as:armorType part:NSUIntegerMax of:NSUIntegerMax];
}

+ (NSData *) armoredData:(NSData *)dataToArmor as:(PGPArmorType)armorType part:(NSUInteger)part of:(NSUInteger)ofParts
{
    NSDictionary *headers = @{@"Creator": @"ObjectivePGP",
                              @"Charset": @"UTF-8"};

    NSMutableString *headerString = [NSMutableString stringWithString:@"-----"];
    NSMutableString *footerString = [NSMutableString stringWithString:@"-----"];
    switch (armorType) {
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
            break;
    }

    [headerString appendString:@"-----\r\n"];
    [footerString appendString:@"-----\r\n"];

    NSMutableString *armoredMessage = [NSMutableString string];
    // - An Armor Header Line, appropriate for the type of data
    [armoredMessage appendString:headerString];

    // - Armor Headers
    for (NSString *key in headers.allKeys) {
        [armoredMessage appendFormat:@"%@: %@\r\n", key, headers[key]];
    }

    // - A blank (zero-length, or containing only whitespace) line
    [armoredMessage appendString:@"\r\n"];

    // - The ASCII-Armored data
    NSString *radix64 = [dataToArmor base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn];
    [armoredMessage appendString:radix64];
    [armoredMessage appendString:@"\r\n"];

    // - An Armor Checksum
    UInt32 checksum = [dataToArmor pgpCRC24];
    UInt8  c[3]; // 24 bit
    c[0] = checksum >> 16;
	c[1] = checksum >> 8;
	c[2] = checksum;

    NSData *checksumData = [NSData dataWithBytes:&c length:sizeof(c)];
    [armoredMessage appendString:@"="];
    [armoredMessage appendString:[checksumData base64EncodedStringWithOptions:(NSDataBase64Encoding76CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn)]];
    [armoredMessage appendString:@"\r\n"];

    // - The Armor Tail, which depends on the Armor Header Line
    [armoredMessage appendString:footerString];

    return [armoredMessage dataUsingEncoding:NSASCIIStringEncoding];
};

@end
