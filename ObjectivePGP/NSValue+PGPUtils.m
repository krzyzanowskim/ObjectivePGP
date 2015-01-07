//
//  NSValue+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "NSValue+PGPUtils.h"

@implementation NSValue (PGPUtils)

- (BOOL) pgp_objCTypeIsEqualTo:(const char *)type
{
    if (!type || strlen(type) == 0)
        return NO;

    if (strcmp([self objCType], type) == 0) {
        return YES;
    }
    return NO;
}

@end
