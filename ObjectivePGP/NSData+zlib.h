//
//  NSData+zlib.h
//
// rfc1950 (zlib format)

#import <Foundation/Foundation.h>
#import <zlib.h>

extern NSString* const ZlibErrorDomain;

@interface NSData (zlib)

- (NSData *)zlibCompressed:(NSError * __autoreleasing *)error;
- (NSData *)zlibDecompressed:(NSError * __autoreleasing *)error;

@end
