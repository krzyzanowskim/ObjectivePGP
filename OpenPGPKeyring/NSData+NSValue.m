//
//  NSData+NSValue.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSData+NSValue.h"

@implementation NSData (NSValue)

+(NSData*) dataWithValue:(NSValue*)value
{
    NSUInteger size;
    const char* encoding = [value objCType];
    NSGetSizeAndAlignment(encoding, &size, NULL);

    void* ptr = malloc(size);
    [value getValue:ptr];
    NSData* data = [NSData dataWithBytes:ptr length:size];
    free(ptr);

    return data;
}

+(NSData*) dataWithNumber:(NSNumber*)number
{
    return [NSData dataWithValue:(NSValue*)number];
}

@end
