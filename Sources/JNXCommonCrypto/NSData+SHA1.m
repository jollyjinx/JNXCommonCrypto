//
//  NSData+ZlibAddition.m
//  JNXLicense Framework
//
//  Created by Patrick Stein on 09.05.07.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSData+SHA1.h"
#import "NSString+hexString.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>

@implementation NSString (SHA1)

- (NSString *)sha1StringNoKey;
{
	return [self sha1StringWithKey:nil];
}
- (NSString *)sha1StringWithKey:(NSData *)keyData;
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha1StringWithKey:keyData];
}
- (NSString *)sha1StringCompatible
{
	return [[[self dataUsingEncoding:NSUTF8StringEncoding] sha1DataCompatible] hexString];
}

@end

@implementation NSData (SHA1)

#if CC_SHA1_DIGEST_LENGTH != 20
#warning SHA1 is not 20 bytes NSData+SHA1 only uses the first 20 bytes
#endif

- (NSString *)sha1StringNoKey;
{
	return [self sha1StringWithKey:nil];
}

- (NSString *)sha1StringWithKey:(NSData *)keyData;
{
	return [[self sha1DataWithKey:keyData] hexString];
}
- (NSData *)sha1DataNoKey;
{
	return [self sha1DataWithKey:nil];
}

- (NSData *)sha1DataWithKey:(NSData *)keyData;
{
	uint8_t	 digest[CC_SHA1_DIGEST_LENGTH]	= {0};

    CCHmac(kCCHmacAlgSHA1, [keyData bytes], [keyData length], [self bytes], [self length], digest);
    return [NSData dataWithBytes:digest length:sizeof(digest)];

}

- (NSData *)sha1DataCompatible
{
	uint8_t	 digest[CC_SHA1_DIGEST_LENGTH]	= {0};

    CC_SHA1( [self bytes], (CC_LONG)[self length], digest);

    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

- (NSString *)sha1StringCompatible
{
	return [[self sha1DataCompatible] hexString];
}

@end


