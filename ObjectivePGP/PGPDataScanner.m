//
//  PGPDataScanner.m
//  
//
//  Created by Scott Morrison on 2024-02-29.
//

#import "PGPDataScanner.h"
#import "PGPFoundation.h"
#import "PGPTypes.h"
#import "NSData+PGPUtils.h"
#import "PGPMacros+Private.h"

@interface PGPDataScanner( )
@property (readwrite,copy,atomic) NSData * data;
@end

@implementation PGPDataScanner
@synthesize data = _data;
@synthesize location = _location;

-(instancetype)init{
    NSAssert(NO,@"Must call initWithData:");
    self = [super init];
    return self;
}

-(instancetype)initWithData:(NSData*)data{
    self = [super init];
    if (self){
        _location = 0;
        _data = data;
    }
    return self;
}
-(BOOL)isAtEnd{
    return self.location>=self.data.length;
}

-(BOOL)scanData:(NSData*)data intoData:(NSData * _Nullable __autoreleasing* _Nullable)dataRef{
    if (dataRef) {
        *dataRef = nil;
    }
    if (data.length == 0){
        return NO;
    }
    let proposedRange = NSMakeRange(self.location,data.length);
    if (NSMaxRange(proposedRange) > self.data.length){
        return NO;
    }
    let compareData = [self.data subdataWithRange:proposedRange];
    if ([data isEqualToData:compareData]){
        self.location+=data.length;
        if (dataRef) *dataRef= compareData;
        return YES;
    }
    return NO;
}

-(BOOL)scanUpToData:(NSData*)data intoData:(NSData * _Nullable __autoreleasing* _Nullable)dataRef{
    let loc = self.location;
    let range = [self.data rangeOfData:data options:0 range:NSMakeRange(loc,self.data.length-loc)];
    if (range.location != NSNotFound){
        if (dataRef) * dataRef = [self.data subdataWithRange:NSMakeRange(loc, range.location-loc)];
        self.location = range.location;
        return self.location > loc;
    }
    return NO;
}

-(BOOL)scanArmoredDataIntoBinaryData:(NSData* _Nullable __autoreleasing* _Nullable)binaryDataRef
                error:(NSError*_Nullable __autoreleasing* _Nullable)error{
    let crlf = [NSData dataWithBytes:"\r\n" length:2];
    let cr = [NSData dataWithBytes:"\r" length:1];
    let lf = [NSData dataWithBytes:"\n" length:1];
    let scanner = self;
    let headerDelimiter = [@"-----" dataUsingEncoding:NSASCIIStringEncoding];
    let startLocation = scanner.location;
    
    if (![scanner scanData:headerDelimiter intoData:nil]){
        // error should have opening header delimeter
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Armoured data must begin with header" }];
        }
        scanner.location = startLocation;
        return NO;
    }
    NSData * beginData;
    if (![scanner scanUpToData:headerDelimiter intoData:&beginData]){
        // error expecting BEGIN
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        scanner.location = startLocation;
        return NO;
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
        scanner.location = startLocation;
        return NO;
    }
    
    if (![scanner scanData:headerDelimiter intoData:nil]){
        // error should have closing header delimeter
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        scanner.location = startLocation;
        return NO;
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
        scanner.location = startLocation;
        return NO;
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
            scanner.location = startLocation;
            return NO;
        }
    }
    // consume empty line after comments;
    if (![scanner scanData:lineBreak intoData:nil]){
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Malformed armor header" }];
        }
        scanner.location = startLocation;
        return NO;
    }
    
    NSData * armorBody;
    if (![scanner scanUpToData:tail intoData:&armorBody] || ![scanner scanData:tail intoData:nil]){
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Tail doesn't match armor header" }];
        }
    }
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
            scanner.location = startLocation;
            return NO;
        }
    }
    if (binaryDataRef){
        *binaryDataRef = binaryData;
    }
    return scanner.location > startLocation;
}
@end
