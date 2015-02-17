//
//  NSData+PGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/02/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (PGP)
- (UInt16) readUInt16BE:(NSRange)range;
- (UInt32) readUInt32BE:(NSRange)range;
@end
