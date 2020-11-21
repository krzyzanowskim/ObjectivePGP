//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPBigNum : NSObject <NSCopying>

@property (nonatomic, readonly) int bitsCount;
@property (nonatomic, readonly) int bytesCount;
@property (nonatomic, readonly) NSData *data;

@end

NS_ASSUME_NONNULL_END
