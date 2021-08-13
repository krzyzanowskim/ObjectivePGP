//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import <Foundation/Foundation.h>
#import "PGPMPI.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPPublicKeyEncryptedSessionKeyParams : NSObject <NSCopying>

@property (nonatomic, copy) NSArray <PGPMPI *> *MPIs; // V

/// Encoded symmetric key (ECDH)
@property (nonatomic, copy, nullable) NSData *ECDH_encodedSymmetricKey; // C

@end

NS_ASSUME_NONNULL_END
