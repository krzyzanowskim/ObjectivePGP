//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/ObjectivePGP-Private.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPUserAttributeImageSubpacket : PGPUserAttributeSubpacket

@property (nonatomic, readonly, nullable) NSData *image;

@end

NS_ASSUME_NONNULL_END
