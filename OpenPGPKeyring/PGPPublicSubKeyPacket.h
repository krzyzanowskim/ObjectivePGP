//
//  PGPPublicSubKey.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 14

#import <Foundation/Foundation.h>
#import "PGPPublicKeyPacket.h"
#import "PGPPacket.h"

@interface PGPPublicSubKeyPacket : PGPPublicKeyPacket <PGPPacket>

@end
