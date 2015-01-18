//
//  NSInputStream+PGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSInputStream (PGP)
- (UInt8) readUInt8;
- (UInt16) readUInt16;
- (UInt32) readUInt32;
@end
