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

NS_ASSUME_NONNULL_BEGIN
@class PGPKeyID;

@interface PGPVerification : NSObject
@property (assign) int verificationCode;
@property (strong,nullable) PGPKeyID* keyID;
@property (strong,nullable) NSError * verificationError;

@end

NS_ASSUME_NONNULL_END
