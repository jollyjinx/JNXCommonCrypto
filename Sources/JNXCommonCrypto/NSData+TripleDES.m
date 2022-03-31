//
//  NSData+_DES.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "NSData+TripleDES.h"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>

@implementation NSString (TripleDES)
- (NSData *)tripleDESEncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] tripleDESEnOrDecrypt:kCCEncrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}
@end


@implementation NSData (TripleDES)

- (NSData *)tripleDESEncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [self tripleDESEnOrDecrypt:kCCEncrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}
- (NSData *)tripleDESDecryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
{
	return [self tripleDESEnOrDecrypt:kCCDecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData];
}

- (NSData *)tripleDESEnOrDecrypt:(BOOL)enordecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)ivData;
{
	NSMutableData	*outputBuffer = [NSMutableData dataWithLength:self.length + kCCBlockSize3DES];
	size_t			movedbytes;
	
	if( kCCSuccess == CCCrypt(enordecrypt,
						kCCAlgorithm3DES,
						kCCOptionPKCS7Padding,
						[keyData bytes],
						kCCKeySize3DES,
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
