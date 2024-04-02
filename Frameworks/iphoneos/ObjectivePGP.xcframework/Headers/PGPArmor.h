//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, PGPArmorType) {
    PGPArmorMessage = 1,
    PGPArmorPublicKey = 2,
    PGPArmorSecretKey = 3,
    PGPArmorMultipartMessagePartXOfY = 4,
    PGPArmorMultipartMessagePartX = 5,
    PGPArmorSignature = 6,
    PGPArmorCleartextSignedMessage = 7, // TODO: -----BEGIN PGP SIGNED MESSAGE-----
};

NS_ASSUME_NONNULL_BEGIN

/// ASCII Armor message.
NS_SWIFT_NAME(Armor) @interface PGPArmor : NSObject

+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type part:(NSUInteger)part of:(NSUInteger)ofParts;

/// Convert binary PGP message to ASCII armored format.
+ (NSString *)armored:(NSData *)data as:(PGPArmorType)type;

/// Convert ASCII armored PGP message to binary format.
+ (nullable NSData *)readArmored:(NSString *)string error:(NSError * __autoreleasing _Nullable *)error;

+ (nullable NSData *)readArmoredData:(NSData*)data error:(NSError * __autoreleasing _Nullable *)error;

/// Whether the data is PGP ASCII armored message.
+ (BOOL)isArmoredData:(NSData *)data;

/// Helper function to convert input data (ASCII or binary) to array of PGP messages.
+ (nullable NSArray<NSData *> *)convertArmoredMessage2BinaryBlocksWhenNecessary:(NSData *)binOrArmorData error:(NSError * __autoreleasing _Nullable *)error;

+ (nullable NSArray<NSData *> *)convertArmoredData2BinaryBlocksWhenNecessary:(NSData *)binOrArmorData error:(NSError * __autoreleasing _Nullable *)error;
@end

NS_ASSUME_NONNULL_END
