//
//  NSData+zlib.m
//
// rfc1950 (zlib format)

#import "NSData+compression.h"
#import <zlib.h>
#import <bzlib.h>

@implementation NSData (compression)

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
	if (Z_OK != deflateInit(&strm, Z_DEFAULT_COMPRESSION)) //FIXME -13 for PGP 2.x
	{
        if (error) {
            NSString *errorMsg = [NSString stringWithCString:strm.msg encoding:NSASCIIStringEncoding];
            *error = [NSError errorWithDomain:@"ZLIB" code:0 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
        }
        return nil;
	}
	
	NSMutableData *compressed = [NSMutableData dataWithLength: deflateBound(&strm, [self length])];
	strm.next_out = [compressed mutableBytes];
	strm.avail_out = (uInt)compressed.length;
	strm.next_in = (void *)[self bytes];
	strm.avail_in = (uInt)[self length];
	
	while (deflate(&strm, Z_FINISH) != Z_STREAM_END)
	{
		// deflate should return Z_STREAM_END on the first call
		[compressed setLength: [compressed length] * 1.5];
		strm.next_out = [compressed mutableBytes] + strm.total_out;
		strm.avail_out = (uInt)(compressed.length - strm.total_out);
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
	strm.avail_out = (unsigned int )[decompressed length];
	strm.next_in = (void *)[self bytes];
	strm.avail_in = (unsigned int)[self length];
	
	while (inflate(&strm, Z_FINISH) != Z_STREAM_END)
	{
		// inflate should return Z_STREAM_END on the first call
		[decompressed setLength: [decompressed length] * 1.5];
		strm.next_out = [decompressed mutableBytes] + strm.total_out;
		strm.avail_out = (unsigned int)([decompressed length] - strm.total_out);
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

- (NSData *)bzip2Decompressed:(NSError * __autoreleasing *)error
{
    int bzret = 0;
    bz_stream stream = {0x00};
    stream.next_in = (void *)[self bytes];
    stream.avail_in = (unsigned int)self.length;
    
    const int buffer_size = 10000;
    NSMutableData *buffer = [NSMutableData dataWithLength:buffer_size];
    stream.next_out = [buffer mutableBytes];
    stream.avail_out = buffer_size;
    
    NSMutableData * decompressed = [NSMutableData data];
    
    BZ2_bzDecompressInit(&stream, 0, NO);
    do {
        bzret = BZ2_bzDecompress(&stream);
        if (bzret != BZ_OK && bzret != BZ_STREAM_END) {
            if (error) {
                *error = [NSError errorWithDomain:@"BZIP2" code:0 userInfo:@{NSLocalizedDescriptionKey: @"BZ2_bzDecompress failed"}];
            }
            BZ2_bzCompressEnd(&stream);
            return nil;
        }
        
        [decompressed appendBytes:[buffer bytes] length:(buffer_size - stream.avail_out)];
        stream.next_out = [buffer mutableBytes];
        stream.avail_out = buffer_size;
    } while(bzret != BZ_STREAM_END);
    
    BZ2_bzDecompressEnd(&stream);
    return decompressed;
}

- (NSData *)bzip2Compressed:(NSError * __autoreleasing *)error
{
    int bzret = 0;
    bz_stream stream = {0x00};
    stream.next_in = (void *)[self bytes];
    stream.avail_in = (unsigned int)self.length;
    unsigned int compression = 9; // should be a value between 1 and 9 inclusive

    const int buffer_size = 10000;
    NSMutableData *buffer = [NSMutableData dataWithLength:buffer_size];
    stream.next_out = [buffer mutableBytes];
    stream.avail_out = buffer_size;
    
    NSMutableData * decompressed = [NSMutableData data];
    
    BZ2_bzCompressInit(&stream, compression, 0, 0);
    do {
        bzret = BZ2_bzCompress(&stream, (stream.avail_in) ? BZ_RUN : BZ_FINISH);
        if (bzret != BZ_RUN_OK && bzret != BZ_STREAM_END) {
            if (error) {
                *error = [NSError errorWithDomain:@"BZIP2" code:0 userInfo:@{NSLocalizedDescriptionKey: @"BZ2_bzCompress failed"}];
            }
            BZ2_bzCompressEnd(&stream);
            return nil;
        }
        
        [decompressed appendBytes:[buffer bytes] length:(buffer_size - stream.avail_out)];
        stream.next_out = [buffer mutableBytes];
        stream.avail_out = buffer_size;
    } while(bzret != BZ_STREAM_END);
    
    BZ2_bzCompressEnd(&stream);
    return decompressed;
}



@end
