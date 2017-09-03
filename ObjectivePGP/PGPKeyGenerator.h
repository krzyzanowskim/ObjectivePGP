//
//  PGPKeyGenerator.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 25/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey;

@interface PGPKeyGenerator : NSObject

@property (nonatomic) int keyBitsLength;
@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPSymmetricAlgorithm cipherAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) UInt8 version;
@property (nonatomic) NSDate *createDate;

- (PGPKey *)generateFor:(NSString *)userID;

@end

NS_ASSUME_NONNULL_END
