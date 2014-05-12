//
//  PGPModificationDetectionCodePacket.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPModificationDetectionCodePacket : PGPPacket

@property (strong) NSData *hashData;

@end
