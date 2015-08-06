//
//  NSData+zlib.h
//
// rfc1950 (zlib format)

#import <Foundation/Foundation.h>
#import <zlib.h>

extern NSString* const ZlibErrorDomain;

@interface NSData (compression)

- (NSData *)zlibCompressed:(NSError * __autoreleasing *)error;
- (NSData *)zlibDecompressed:(NSError * __autoreleasing *)error compressionType:(int)compressionType;

- (NSData *)bzip2Decompressed:(NSError * __autoreleasing *)error;
- (NSData *)bzip2Compressed:(NSError * __autoreleasing *)error;

@end
