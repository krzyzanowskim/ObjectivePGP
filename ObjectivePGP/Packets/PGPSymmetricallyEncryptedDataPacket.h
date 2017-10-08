//
//  PGPSymmetricallyEncryptedDataPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPSymmetricallyEncryptedDataPacket : PGPPacket <NSCopying>

@property (nonatomic, copy) NSData *encryptedData;

@end

NS_ASSUME_NONNULL_END
