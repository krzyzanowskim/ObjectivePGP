//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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

