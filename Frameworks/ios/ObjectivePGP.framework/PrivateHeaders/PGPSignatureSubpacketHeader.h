//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacketHeader : NSObject

@property (nonatomic) PGPSignatureSubpacketType type;
@property (nonatomic) NSUInteger headerLength;
@property (nonatomic) NSUInteger bodyLength;

@end

NS_ASSUME_NONNULL_END
