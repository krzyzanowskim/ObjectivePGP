//
//  PGPSignatureSubpacketHeader.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
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
