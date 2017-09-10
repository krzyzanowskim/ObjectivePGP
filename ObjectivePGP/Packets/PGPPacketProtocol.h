//
//  PGPPacketProtocol.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@protocol PGPPacketProtocol <NSObject>

@property (nonatomic, readonly) PGPPacketTag tag;

@end
