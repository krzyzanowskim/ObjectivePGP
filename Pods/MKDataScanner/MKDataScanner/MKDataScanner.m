//
//  MKDataScanner.m
//  MKDataScanner
//
//  Created by Marcin Krzyzanowski on 09/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "MKDataScanner.h"
#import "MKDataProvider.h"
#import "MKDataScannerStreamFileProvider.h"
#import "MKDataScannerDispatchIOFileProvider.h"
#import "MKDataScannerDataProvider.h"

@interface MKDataScanner ()
@property (strong) id <MKDataProvider> provider;
@end

@implementation MKDataScanner

- (instancetype) initWithFileURL:(NSURL *)fileURL provider:(MKDataFileHandlerType)providerType;
{
    NSParameterAssert(fileURL.fileURL);
    if (!fileURL) {
        return nil;
    }
    
    if (self = [self init]) {
        switch (providerType) {
            case MKDataFileDispatchIOProvider:
                _provider = [[MKDataScannerDispatchIOFileProvider alloc] initWithFileURL:fileURL];
                break;
            case MKDataFileStreamProvider:
                _provider = [[MKDataScannerStreamFileProvider alloc] initWithFileURL:fileURL];
                break;
            default:
                _provider = [[MKDataScannerDispatchIOFileProvider alloc] initWithFileURL:fileURL];
                break;
        }
    }
    return self;
}

- (instancetype) initWithFileURL:(NSURL *)fileURL
{
    if (self = [self initWithFileURL:fileURL provider:MKDataFileDefaultProvider]) {
        
    }
    return self;
}

- (instancetype) initWithData:(NSData *)data
{
    NSParameterAssert(data);
    if (!data) {
        return nil;
    }
    
    if (self = [self init]) {
        _provider = [[MKDataScannerDataProvider alloc] initWithData:data];
    }
    return self;
}

- (NSUInteger)scanLocation
{
    return [self.provider offset];
}

- (void)setScanLocation:(NSUInteger)scanLocation
{
    [self.provider setOffset:scanLocation];
}

- (BOOL)isAtEnd
{
    return [self.provider isAtEnd];
}


/**
 *  Scans the data until a byte from a given set is encountered, accumulating bytes into a data that’s returned by reference.
 *
 *  @param stopSet   The set of bytes up to which to scan.
 *  @param dataValue Upon return, contains the bytes scanned.
 *
 *  @return YES if the receiver scanned any bytes, otherwise NO.
 */
- (BOOL) scanUpToBytesFromSet:(NSSet *)stopSet intoData:(NSData * __autoreleasing *)dataValue
{
    NSParameterAssert(stopSet);
    NSMutableData *scannedData = [NSMutableData data];
    
    NSUInteger location = self.scanLocation;
    NSData *currentBlock = nil;
    while ((currentBlock = [self.provider dataForRange:(NSRange){location,sizeof(Byte)}])) {
        for (NSNumber *stopByteNumber in stopSet) {
            NSAssert(stopByteNumber.unsignedIntValue <= 255, @"Invalid set");
            Byte stopByte = stopByteNumber.unsignedShortValue;
            Byte blockByte = 0;
            [currentBlock getBytes:&blockByte length:sizeof(Byte)];
            if (blockByte == stopByte) {
                [scannedData appendData:currentBlock];
                if (dataValue) {
                    *dataValue = [scannedData copy];
                }
                self.scanLocation = location;
                return YES;
            }
        }
        location += currentBlock.length;
        [scannedData appendData:currentBlock];
    }
    return NO;
}

- (BOOL)scanUpToBytes:(const void *)bytes length:(int)length intoData:(NSData * __autoreleasing *)dataValue
{
    NSData *data = [NSData dataWithBytes:bytes length:length];
    return [self scanUpToData:data intoData:dataValue];
}

- (BOOL)scanUpToData:(NSData *)stopData intoData:(NSData * __autoreleasing *)dataValue
{
    NSParameterAssert(stopData);
    NSMutableData *scannedData = [NSMutableData data];

    NSUInteger location = self.scanLocation;
    NSData *currentBlock = nil;
    while ((currentBlock = [self.provider dataForRange:(NSRange){location,stopData.length * 2}])) {
        NSRange searchRange = [currentBlock rangeOfData:stopData options:0 range:(NSRange){0,currentBlock.length}];
        if (searchRange.location != NSNotFound) {
            if (dataValue) {
                [scannedData appendData:[currentBlock subdataWithRange:(NSRange){0,searchRange.location}]];
                *dataValue = [scannedData copy];
            }
            self.scanLocation = location + searchRange.location;
            return YES;
        }
        location += currentBlock.length;
        [scannedData appendData:currentBlock];
    }
    return NO;
}

- (BOOL)scanData:(NSData *)data intoData:(NSData **)dataValue
{
    NSData *scannedBlock = nil;
    if (![self.provider isAtEnd] && (scannedBlock = [self.provider dataForRange:(NSRange){self.scanLocation,data.length}])) {
        if ([scannedBlock isEqualToData:data]) {
            if (dataValue) {
                *dataValue = scannedBlock;
            }
            self.scanLocation += scannedBlock.length;
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)scanInteger:(NSInteger *)value
{
    NSData *scannedBlock = nil;
    if (![self.provider isAtEnd] && (scannedBlock = [self.provider dataForRange:(NSRange){self.scanLocation,sizeof(NSInteger)}])) {
        if (scannedBlock.length != sizeof(NSInteger)) {
            if (value) {
                *value = scannedBlock.length > sizeof(NSInteger) ? INT_MAX : INT_MIN;
            }
            return NO;
        }
        NSInteger scannedValue;
        [scannedBlock getBytes:&scannedValue length:scannedBlock.length];
        if (value) {
            *value = scannedValue;
        }
        self.scanLocation = self.scanLocation + scannedBlock.length;
        return YES;
    }
    return NO;
}

- (BOOL)scanByte:(Byte *)value
{
    NSData *scannedBlock = nil;
    if (![self.provider isAtEnd] && (scannedBlock = [self.provider dataForRange:(NSRange){self.scanLocation,sizeof(UInt8)}])) {
        if (scannedBlock.length < sizeof(UInt8)) {
            return NO;
        }
        NSInteger scannedValue;
        [scannedBlock getBytes:&scannedValue length:scannedBlock.length];
        if (value) {
            *value = scannedValue;
        }
        self.scanLocation = self.scanLocation + scannedBlock.length;
        return YES;
    }
    return NO;
}

- (BOOL) scanBytes:(Byte *)buffer length:(int)length
{
    int bytesCount = 0;
    while (bytesCount < length) {
        
        Byte byte;
        if (![self scanByte:&byte]) {
            return NO;
        }
        
        buffer[bytesCount] = byte;
        bytesCount++;
    }
    return YES;
}

+ (instancetype) scannerWithFileURL:(NSURL *)fileURL
{
    return [[MKDataScanner alloc] initWithFileURL:fileURL];
}

+ (instancetype) scannerWithData:(NSData *)data
{
    return [[MKDataScanner alloc] initWithData:data];
}

@end
