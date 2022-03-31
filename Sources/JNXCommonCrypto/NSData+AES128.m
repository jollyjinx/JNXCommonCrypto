//
//  NSData+AES128.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-23.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSData+AES128.h"
#import "NSData+randomGenerator.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>


@implementation NSString (AES128)
- (NSData *)AES128EncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] AES128EnOrDecrypt:kCCEncrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}
@end


@implementation NSData (AES128)


+ (NSData *)randomAES128Cipher;
{
	return [NSData randomDataWithLength:2*kCCKeySizeAES128];
}

- (NSData *)AES128EncryptWithCipher:(NSData *)cipherData;
{
	return [self AES128EnOrDecrypt:kCCEncrypt withCipher:(NSData *)cipherData];
}
- (NSData *)AES128DecryptWithCipher:(NSData *)cipherData;
{
	return [self AES128EnOrDecrypt:kCCDecrypt withCipher:(NSData *)cipherData];
}

- (NSData *)AES128EnOrDecrypt:(BOOL)enordecrypt withCipher:(NSData *)cipherData
{
	if( [cipherData length] != (2*kCCKeySizeAES128) )
	{
		return nil;
	}

	NSData	*keyData 		= [cipherData subdataWithRange:NSMakeRange(0,kCCKeySizeAES128)];
	NSData 	*iVectorData	= [cipherData subdataWithRange:NSMakeRange(kCCKeySizeAES128,kCCKeySizeAES128)];
	
//	DJLog(@"keyData:%@ iVectorData:%@ enordecrypt:%d",keyData,iVectorData,enordecrypt);
	return [self AES128EnOrDecrypt:enordecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}




- (NSData *)AES128EncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [self AES128EnOrDecrypt:kCCEncrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}
- (NSData *)AES128DecryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [self AES128EnOrDecrypt:kCCDecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}

- (NSData *)AES128EnOrDecrypt:(BOOL)enordecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)ivData;
{
	NSMutableData	*outputBuffer = [NSMutableData dataWithLength:self.length + (2*kCCKeySizeAES128) ];
	size_t			movedbytes;
	
	if( kCCSuccess == CCCrypt(enordecrypt,
						kCCAlgorithmAES128,
						kCCOptionPKCS7Padding,
						[keyData bytes],
						kCCKeySizeAES128,
						[ivData bytes], 
						[self bytes],
						[self length],
						(void*)[outputBuffer bytes], // output
						outputBuffer.length,
						&movedbytes) )
	{
		[outputBuffer setLength:movedbytes];
		return outputBuffer;
	}
	return nil;
}


@end
