
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#define PGPCast(obj, c) ((c * _Nullable) _pgp__cast(obj, c.class))

id _Nullable _pgp__cast(id _Nullable obj, Class objClass);

BOOL PGPEqualObjects(id _Nullable obj1, id _Nullable obj2);

@interface PGPFoundation : NSObject

@end

NS_ASSUME_NONNULL_END
