//
//  NSData+zlib.m
//
// rfc1950 (zlib format)

#import "NSData+zlib.h"
#import <zlib.h>

@implementation NSData (zlib)

- (NSData *)zlibCompressed:(NSError * __autoreleasing *)error
{
	if ([self length] == 0)
	{
		return [NSData data];
	}
	
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	if (Z_OK != deflateInit(&strm, Z_DEFAULT_COMPRESSION))
	{
        if (error) {
            NSString *errorMsg = [NSString stringWithCString:strm.msg encoding:NSASCIIStringEncoding];
            *error = [NSError errorWithDomain:@"ZLIB" code:0 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
        }
        return nil;
	}
	
	NSMutableData *compressed = [NSMutableData dataWithLength: deflateBound(&strm, [self length])];
	strm.next_out = [compressed mutableBytes];
	strm.avail_out = [compressed length];
	strm.next_in = (void *)[self bytes];
	strm.avail_in = [self length];
	
	while (deflate(&strm, Z_FINISH) != Z_STREAM_END)
	{
		// deflate should return Z_STREAM_END on the first call
		[compressed setLength: [compressed length] * 1.5];
		strm.next_out = [compressed mutableBytes] + strm.total_out;
		strm.avail_out = [compressed length] - strm.total_out;
	}
	
	[compressed setLength: strm.total_out];
    
	int status = deflateEnd(&strm);
    if (status != Z_OK) {
        if (error) {
            NSString *errorMsg = [NSString stringWithCString:strm.msg encoding:NSASCIIStringEncoding];
            *error = [NSError errorWithDomain:@"ZLIB" code:0 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
        }
        return nil;
    }
	
	return compressed;
}

- (NSData *)zlibDecompressed:(NSError * __autoreleasing *)error
{
	if ([self length] == 0)
	{
		return [NSData data];
	}
	
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	if (Z_OK != inflateInit(&strm))
	{
        if (error) {
            NSString *errorMsg = [NSString stringWithCString:strm.msg encoding:NSASCIIStringEncoding];
            *error = [NSError errorWithDomain:@"ZLIB" code:0 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
        }
        return nil;
	}
	
	NSMutableData *decompressed = [NSMutableData dataWithLength: [self length]*2.5];
	strm.next_out = [decompressed mutableBytes];
	strm.avail_out = [decompressed length];
	strm.next_in = (void *)[self bytes];
	strm.avail_in = [self length];
	
	while (inflate(&strm, Z_FINISH) != Z_STREAM_END)
	{
		// inflate should return Z_STREAM_END on the first call
		[decompressed setLength: [decompressed length] * 1.5];
		strm.next_out = [decompressed mutableBytes] + strm.total_out;
		strm.avail_out = [decompressed length] - strm.total_out;
	}
	
	[decompressed setLength: strm.total_out];
    
	int status = inflateEnd(&strm);
    if (status != Z_OK) {
        if (error) {
            NSString *errorMsg = [NSString stringWithCString:strm.msg encoding:NSASCIIStringEncoding];
            *error = [NSError errorWithDomain:@"ZLIB" code:0 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
        }
        return nil;
    }
	
	return decompressed;
}

@end
