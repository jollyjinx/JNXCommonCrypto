//
//  NSData+PBKDF2SHA1TripleDESEncryption.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/1/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>

#import "JNXCommonCrypto.h"
#import "JNXLog.h"


@implementation NSString (PBKDF2SHA1TripleDESEncryption)

- (NSData *)encryptStringWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] encryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature];
}
@end


@implementation NSData (PBKDF2SHA1TripleDESEncryption)


- (NSData *)encryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;
{
	NSData	*dataToEncrypt;
    
    if( usesignature )
    {
    	NSMutableData	*signatureData 	= [[self sha1DataNoKey] mutableCopy];
        [signatureData appendData:[self copy]];
        
    	dataToEncrypt = [signatureData copy];
    }
    else
    {	
		dataToEncrypt = [self copy];
    }
    
	return  [dataToEncrypt tripleDESEncryptWithKey:keyData initalizationVector:ivData];
}


- (NSData *)decryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;
{
	NSData	*decryptedData	= [self tripleDESDecryptWithKey:keyData initalizationVector:ivData];
    
    if( !decryptedData || !usesignature )
    {
    	return decryptedData;
    }
    
    if( [decryptedData length] < CC_SHA1_DIGEST_LENGTH )
    {
    	return nil;
    }
    
    NSData	*signaturePart	= [decryptedData subdataWithRange:NSMakeRange(0,CC_SHA1_DIGEST_LENGTH)];
    NSData	*decryptedPart	= [decryptedData subdataWithRange:NSMakeRange(CC_SHA1_DIGEST_LENGTH,[decryptedData length]-CC_SHA1_DIGEST_LENGTH)];

    if( [[decryptedPart sha1DataNoKey] isEqualToData:signaturePart] )
    {
    	return decryptedPart;
    }
    return nil;
}

- (NSString *)decryptStringWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;
{
	NSData *returnData =[self decryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature];
    
    if( returnData )
    {
    	return [[NSString alloc] initWithData:returnData encoding:NSUTF8StringEncoding];
    }
	return nil;
}


- (NSData *)encryptDataWithPassphrase:(NSString *)passPhrase salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
{
	return [self encryptDataWithPassword:[passPhrase dataUsingEncoding:NSUTF8StringEncoding] salt:saltData pbkdf2Iterations:iterations initialisationVector:ivData];
}
- (NSData *)decryptDataWithPassphrase:(NSString *)passPhrase salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
{
	return [self decryptDataWithPassword:[passPhrase dataUsingEncoding:NSUTF8StringEncoding] salt:saltData pbkdf2Iterations:iterations initialisationVector:ivData];
}


- (NSData *)encryptDataWithPassword:(NSData *)passwordData salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
{
	NSAssert(passwordData,@"No passwordData");
	NSAssert(saltData,@"No saltData");
	NSAssert(iterations,@"No iterations");
	NSAssert(ivData,@"No ivData");

	NSData 	*hashedPasswordData	= [passwordData pbkdf2hashWithSalt:saltData iterations:[iterations intValue]];
	NSAssert(hashedPasswordData,@"Hashing of passwordData failed");

	NSData	*encryptedData		= [self encryptWithKey:hashedPasswordData initalizationVector:ivData useSignature:YES];
	NSAssert(encryptedData,@"Encryption failed");

	return encryptedData;
}

- (NSData *)decryptDataWithPassword:(NSData *)passwordData salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
{
	NSAssert(passwordData,@"No passwordData");
	NSAssert(saltData,@"No saltData");
	NSAssert(iterations,@"No iterations");
	NSAssert(ivData,@"No ivData");

	NSData 	*hashedPasswordData	= [passwordData pbkdf2hashWithSalt:saltData iterations:[iterations intValue]];

	if( !hashedPasswordData )
	{
		NSAssert(hashedPasswordData,@"Hashing of passwordData failed");
		DJLog(@"Hashing of passwordData failed");
		return nil;
	}

	NSData	*decryptedData		= [self decryptWithKey:hashedPasswordData initalizationVector:ivData useSignature:YES];

	if( ! decryptedData )
	{
		JLog(@"Decrypting of data failed");
	}
	return decryptedData;
}


@end
