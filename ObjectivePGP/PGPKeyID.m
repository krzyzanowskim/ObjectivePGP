//
//  PGPKeyID.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 20/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKeyID.h"
#import "PGPKey.h"
#import "PGPFunctions.h"

@interface PGPKeyID ()
@property (copy, readwrite) NSData *octetsData;
@end

@implementation PGPKeyID

- (instancetype) initWithBytes:(const void *)bytes length:(NSUInteger)length
{
    if (self = [super init]) {
        _octetsData = [NSData dataWithBytes:bytes length:length];
    }
    return self;
}


- (NSString *) description
{
    NSData *lKey = self.octetsData;
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:lKey.length * 2];
    const unsigned char *buf = lKey.bytes;
    for (NSUInteger i = 0; i < lKey.length; ++i) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    return [sbuf copy];
}

- (NSUInteger)hash
{
    const NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + [_octetsData hash];
    return result;
}

- (BOOL)isEqual:(id)object
{
    if (self == object) {
        return YES;
    }
    
    if ([self class] != [object class]) {
        return NO;
    }
    
    PGPKeyID *other = object;
    return [self.octetsData isEqualToData:other.octetsData];
}

- (BOOL) isEqualToKeyID:(PGPKeyID *)keyID
{
    return [self isEqual:keyID];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone
{
    PGPKeyID *copy = [[PGPKeyID alloc] init];
    copy.octetsData = self.octetsData;
    return copy;
}
@end
