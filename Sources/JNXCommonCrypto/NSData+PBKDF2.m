//
//  NSData+PBKDF2.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>

#import "NSData+PBKDF2.h"
#import "NSData+randomGenerator.h"

//@import JNXFree;
#import "JNXLog.h"


@implementation NSString (PBKDF2)

- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] pbkdf2hashWithSalt:saltData];
}
- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] pbkdf2hashWithSalt:saltData iterations:iterations];
}
- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData	iterations:(NSUInteger)iterations	keyLength:(NSUInteger)keylength
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] pbkdf2hashWithSalt:saltData	iterations:(NSUInteger)iterations	keyLength:(NSUInteger)keylength];
}
@end


@implementation NSData (PBKDF2)

+ (NSNumber *)pbkdf2IterationsOnCurrentHardware;
{
	static	NSUInteger 		iterationsoncurrenthardware = TARGET_OS_MAC?10000:1000;
	static dispatch_once_t	onceToken;
	dispatch_once(&onceToken,
	^{
		CFAbsoluteTime	timedifference;

		do
		{
			NSData	*dataToHash	= [NSData randomDataWithLength:kCCKeySize3DES];
			NSData	*randomSalt	= [NSData randomSalt];

			CFAbsoluteTime	starttime	= CFAbsoluteTimeGetCurrent();

			[dataToHash pbkdf2hashWithSalt:randomSalt iterations:iterationsoncurrenthardware keyLength:kCCKeySize3DES];

			timedifference = CFAbsoluteTimeGetCurrent() - starttime;

			if( timedifference < 0.1 )
			{
				DJLog(@"%ld iterations took: %8.3fs - too fast",(long)iterationsoncurrenthardware,timedifference);
				iterationsoncurrenthardware += arc4random_uniform( (uint32_t)iterationsoncurrenthardware/2);
			}
		}
		while( timedifference < 0.1 );

		iterationsoncurrenthardware	= MAX(1000,iterationsoncurrenthardware);

		DJLog(@"Using %ld iterations took: %8.3fs",(long)iterationsoncurrenthardware,timedifference);
	});
	return @(iterationsoncurrenthardware+arc4random_uniform( (uint32_t)iterationsoncurrenthardware/2));
}

- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData;
{
    return [self pbkdf2hashWithSalt:saltData	iterations:1000	keyLength:kCCKeySize3DES];
}

- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations;
{
    return [self pbkdf2hashWithSalt:saltData	iterations:iterations	keyLength:kCCKeySize3DES];
}

- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData	iterations:(NSUInteger)iterations	keyLength:(NSUInteger)keylength;
{
	NSMutableData	*outputData		= [NSMutableData dataWithLength:keylength];
    void 			*outputbuffer	= [outputData mutableBytes];

    const void 		*passwordbytes	= [self bytes];
    size_t			passwordlength	= [self length];

	if( ! passwordlength )
	{
		passwordbytes = (const void *)"";
	}

	const void		*saltbytes		= [saltData bytes];
    size_t			saltlength		= [saltData length];
    
	unsigned char digtmp[CC_SHA1_DIGEST_LENGTH], *p, itmp[4];
	int cplen, j, k, tkeylen;
	unsigned long i = 1;
	p = outputbuffer;
	tkeylen = (int)keylength;
	CCHmacContext hmaccontext;

	while( tkeylen )
	{
		if(	tkeylen > CC_SHA1_DIGEST_LENGTH)
		{
			cplen = CC_SHA1_DIGEST_LENGTH;
		}
		else
		{
			cplen = tkeylen;
		}
		itmp[0] = (unsigned char)((i >> 24) & 0xff);
		itmp[1] = (unsigned char)((i >> 16) & 0xff);
		itmp[2] = (unsigned char)((i >> 8) & 0xff);
		itmp[3] = (unsigned char)(i & 0xff);
		CCHmacInit(&hmaccontext, kCCHmacAlgSHA1, passwordbytes, passwordlength);
		CCHmacUpdate(&hmaccontext, saltbytes, saltlength);
		CCHmacUpdate(&hmaccontext, itmp, 4);
		CCHmacFinal(&hmaccontext, digtmp);
		memcpy(p, digtmp, cplen);

		for(j = 1; j < iterations; j++) {
			CCHmac(kCCHmacAlgSHA1, passwordbytes, passwordlength, digtmp, CC_SHA1_DIGEST_LENGTH, digtmp);
			for(k = 0; k < cplen; k++) p[k] ^= digtmp[k];
		}

		tkeylen -= cplen;
		i++;
		p+= cplen;
	}
	return [outputData copy];
}

@end
