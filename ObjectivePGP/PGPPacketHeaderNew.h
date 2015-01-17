//
//  PGPPacketHeaderNew.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeader.h"

@interface PGPPacketHeaderNew : PGPPacketHeader <PGPPacketHeader>
- (instancetype)initWithData:(NSData *)headerData;
@end
