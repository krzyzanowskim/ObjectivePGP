//
//  PGPUserAttributeSubpacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface PGPUserAttributeSubpacket : NSObject

// Subpacket types 100 through 110 are reserved for private or experimental use.
@property (assign) UInt8 type;
// Value
@property (strong) NSData *valueData;

@end
