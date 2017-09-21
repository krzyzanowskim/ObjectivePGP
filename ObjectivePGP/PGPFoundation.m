//
//  PGPFoundation.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPFoundation.h"
#import "PGPMacros+Private.h"

@implementation PGPFoundation

@end

OBJC_EXTERN inline id _pgp__cast(id obj, Class objClass) {
    NSCParameterAssert(objClass);
    return [obj isKindOfClass:objClass] ? obj : nil;
}

BOOL PGPEqualObjects(id _Nullable obj1, id _Nullable obj2) {
    return obj1 == obj2 || [obj1 isEqual:obj2];
}

