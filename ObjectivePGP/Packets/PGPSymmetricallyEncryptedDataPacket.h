//
//  PGPSymmetricallyEncryptedDataPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPSymmetricallyEncryptedDataPacket : PGPPacket <NSCopying>

@property (nonatomic, copy) NSData *encryptedData;

@end
