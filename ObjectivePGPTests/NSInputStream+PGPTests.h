//
//  NSInputStream+PGPTests.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSInputStream (PGPTests)

+ (NSInputStream *) inputStreamWithBytes:(UInt8[])bytes length:(int)length;

@end
