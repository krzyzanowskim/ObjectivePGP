//
//  MKDataScannerDataProvider.m
//  MKDataScanner
//
//  Created by Marcin Krzyzanowski on 10/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "MKDataScannerDataProvider.h"

@interface MKDataScannerDataProvider ()
@property (copy) NSData *data;
@property (assign) NSUInteger offset;
@end

@implementation MKDataScannerDataProvider

- (instancetype)initWithData:(NSData *)data
{
    if (self = [self init]) {
        _data = data;
    }
    return self;
}

#pragma mark - MKDataProvider

- (NSData *)dataForRange:(NSRange)range
{
    return [self.data subdataWithRange:range];
}

- (BOOL)isAtEnd
{
    return (self.offset < self.data.length);
}

- (NSUInteger)size
{
    return self.data.length;
}

@end
