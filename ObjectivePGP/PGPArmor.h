//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, PGPArmorType) {
    PGPArmorTypeMessage = 1,
    PGPArmorTypePublicKey = 2,
    PGPArmorTypeSecretKey = 3,
    PGPArmorTypeMultipartMessagePartXOfY = 4,
    PGPArmorTypeMultipartMessagePartX = 5,
    PGPArmorTypeSignature = 6,
    PGPArmorCleartextSignedMessage = 7, // TODO: -----BEGIN PGP SIGNED MESSAGE-----
};

NS_ASSUME_NONNULL_BEGIN

/// ASCII Armor message.
NS_SWIFT_NAME(Armor) @interface PGPArmor : NSObject

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type part:(NSUInteger)part of:(NSUInteger)ofParts;
+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type;

+ (nullable NSData *)readArmored:(NSString *)string error:(NSError * __autoreleasing _Nullable *)error;

+ (BOOL)isArmoredData:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
