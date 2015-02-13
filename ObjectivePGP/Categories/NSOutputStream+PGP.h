//
//  NSOutputStream+PGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/02/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSOutputStream (PGP)
- (BOOL) writeUInt8:(UInt8)value;
- (BOOL) writeUInt16:(UInt16)value;
- (BOOL) writeUInt32:(UInt32)value;
- (BOOL) writeData:(NSData *)data;
@end
