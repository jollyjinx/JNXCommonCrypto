//
//  NSData+RSAPublicKeyEncryption.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-10.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//


//#import <openssl/opensslv.h>
//
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/ripemd.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>


#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#import "NSData+RSAPublicKeyEncryption.h"
#import "NSData+SHA1.h"
#import "NSData+PEM.h"

#import "JNXLog.h"

#undef DEBUG
#define DEBUG 0

@interface NSData (RSAPublicKeyEncryptionPrivate) 
+ (NSData *)createNewPrivateKeyWithLength:(NSUInteger)length;
+ (NSData *)publicKeyFromPrivateKey:(NSData *)privateKeyData;
@end



@implementation NSData (RSAPublicKeyEncryption)

+ (NSArray *)newPrivatePublicKeyPairWithLength:(NSUInteger)length;
{
	NSData *privateKey 	= [self createNewPrivateKeyWithLength:length];
	NSData *publicKey 	= [self publicKeyFromPrivateKey:privateKey];
	
	if( privateKey && (privateKey.length>=(length/8)) && publicKey )
	{
		return [NSArray arrayWithObjects:privateKey,publicKey, nil];
	}
	return nil;
}


+ (NSData *)createNewPrivateKeyWithLength:(NSUInteger)length;
{
    RSA     *key = RSA_new();
	BIGNUM  *exponent = BN_new();

    BN_set_word(exponent, RSA_F4);
    int keylength = (int)length;

    do
	{
        // int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
		RSA_generate_key_ex(key,keylength, exponent, NULL);
    } 
	while(1 != RSA_check_key(key) );

    BIO *bio = BIO_new(BIO_s_mem());

    if( !PEM_write_bio_RSAPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) )
    {
        JLog(@"cannot write private key to memory (PEM_write_bio_RSAPrivateKey)");
		BIO_free(bio);
  		RSA_free(key);
        return nil;
    }
    RSA_free(key);

    char 	*pbio_data		= NULL;
    long 	resultlength	= BIO_get_mem_data(bio, &pbio_data);
	NSData	*result			= nil;
	
	if( length > 0 )
	{
		result 	= [NSData dataWithBytes:pbio_data length:resultlength];
	}

    BIO_free(bio);

    return result;

}
+ (NSData *)publicKeyFromPrivateKey:(NSData *)privateKeyData
{
    BIO *privateBIO = NULL;
    RSA *privateRSA = NULL;
	
    if( !(privateBIO = BIO_new_mem_buf((unsigned char*)[privateKeyData bytes],(int)[privateKeyData length])) )
    {
        JLog(@"BIO_new_mem_buf() failed!");
        return nil;
    }

    if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL))
    {
        JLog(@"PEM_read_bio_RSAPrivateKey() failed");
		BIO_free(privateBIO);
        return nil;
    }
	
	unsigned long check = RSA_check_key(privateRSA);

    if( 1 != check )												// RSA_check_key() returns 1 if valid
    {
        JLog(@"RSA_check_key() failed with result %lu!", check);
		BIO_free(privateBIO);
		RSA_free(privateRSA);
        return nil;
    }

    BIO *bio = BIO_new(BIO_s_mem());
	if( !bio )
	{
		JLog(@"Cannot create Bio_new");
		BIO_free(privateBIO);
		RSA_free(privateRSA);
		return nil;
	}

    if (!PEM_write_bio_RSAPublicKey(bio, privateRSA))
    {
        JLog(@"cannot write public key to memory");
		BIO_free(privateBIO);
		RSA_free(privateRSA);
   		BIO_free(bio);
	    return nil;
    }
	
    char 	*pbio_data		= NULL;
    long 	resultlength	= BIO_get_mem_data(bio, &pbio_data);
	NSData	*result			= nil;
	
	if( resultlength > 0 )
	{
    	result = [NSData dataWithBytes:pbio_data length:resultlength];
	}
	
	BIO_free(privateBIO);
	RSA_free(privateRSA);
    BIO_free(bio);

    return result;
}


- (NSData *)encryptWithPublicKey:(NSData *)publicKeyData
{
        if( publicKeyData == nil)
        {
			return nil;
        }

        BIO *publicBIO = NULL;
        RSA *publicRSA = NULL;

        if(!(publicBIO = BIO_new_mem_buf((unsigned char*)[publicKeyData bytes], (int) [publicKeyData length])))
        {
            JLog(@"BIO_new_mem_buf() failed!");
            return nil;
        }
		if(!PEM_read_bio_RSAPublicKey(publicBIO, &publicRSA, NULL, NULL))
		{
			JLog(@"PEM_read_bio_RSAPublicKey() failed!");
			BIO_free(publicBIO);
			return nil;
		}

        void 			*outbuf	= (unsigned char *)malloc(RSA_size(publicRSA));
		int 			outlen;

		if( !outbuf )
		{	
			JLog(@"Could not malloc buffer.");
			RSA_free(publicRSA);
			BIO_free(publicBIO);
			return nil;
		}

        if(!(outlen = RSA_public_encrypt( (int)[self length], [self bytes], (unsigned char*)outbuf, publicRSA, RSA_PKCS1_PADDING)))
        {
            JLog(@"RSA_public_encrypt failed!");
			RSA_free(publicRSA);
			BIO_free(publicBIO);
			free(outbuf);
            return nil;
        }

        if(outlen == -1)
        {
            JLog(@"Encrypt error: %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error()));
			RSA_free(publicRSA);
			BIO_free(publicBIO);
			free(outbuf);
            return nil;
        }
		if( outlen < 1 )
		{
			JLog(@"Encrypted Data length = 0");
			RSA_free(publicRSA);
			BIO_free(publicBIO);
			free(outbuf);
			return nil;
		}

		RSA_free(publicRSA);
		BIO_free(publicBIO);

		NSData	*encryptedData = [NSData dataWithBytes:outbuf length:outlen];
		
		free(outbuf);

		return encryptedData;
}


- (NSData *)decryptWithPrivateKey:(NSData *)privateKeyData
{
	if( !privateKeyData )
	{
		return nil;
	}

	BIO *privateBIO = NULL;
	RSA *privateRSA = NULL;

	if(!(privateBIO = BIO_new_mem_buf((unsigned char*)[privateKeyData bytes], (int) [privateKeyData length])))
	{
		JLog(@"BIO_new_mem_buf() failed!");
		return nil;
	}

	if(!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL))
	{
		JLog(@"PEM_read_bio_RSAPrivateKey() failed!");
		BIO_free(privateBIO);
		return nil;
	}

	// RSA_check_key() returns 1 if rsa is a valid RSA key, and 0 otherwise.

	unsigned long check = RSA_check_key(privateRSA);
	if(check != 1)
	{
		JLog(@"RSA_check_key() failed with result %lu!", check);
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		return nil;
	}

	// RSA_size() returns the RSA modulus size in bytes.
	// It can be used to determine how much memory must be allocated for an RSA encrypted value.

	void 			*outbuf	= (unsigned char *)malloc(RSA_size(privateRSA));
	int 			outlen;

	if( !outbuf )
	{	
		JLog(@"Could not malloc buffer.");
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		return nil;
	}


	if(!(outlen = RSA_private_decrypt( (int)[self length], [self bytes], outbuf, privateRSA, RSA_PKCS1_PADDING)))
	{
		JLog(@"RSA_private_decrypt() failed!");
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		free(outbuf);
		return nil;
	}

	if(outlen == -1)
	{
		JLog(@"Decrypt error: %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error()));
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		free(outbuf);
		return nil;
	}
	
	if( outlen < 1 )
	{
		JLog(@"Encrypted Data length = 0");
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		free(outbuf);
		return nil;
	}


	NSData	*decryptedData = [NSData dataWithBytes:outbuf length:outlen];
	
	RSA_free(privateRSA);
	BIO_free(privateBIO);
	free(outbuf);

	return decryptedData;
}




- (NSData *)signatureWithPrivateKey:(NSData *)privateKeyData
{
	if( !privateKeyData )
	{
		return nil;
	}

	BIO *privateBIO = NULL;
	RSA *privateRSA = NULL;

	if(!(privateBIO = BIO_new_mem_buf((unsigned char*)[privateKeyData bytes], (int) [privateKeyData length])))
	{
		JLog(@"BIO_new_mem_buf() failed!");
		return nil;
	}

	if(!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL))
	{
		JLog(@"PEM_read_bio_RSAPrivateKey() failed!");		
		BIO_free(privateBIO);
		return nil;
	}

	// RSA_check_key() returns 1 if rsa is a valid RSA key, and 0 otherwise.

	unsigned long check = RSA_check_key(privateRSA);
	if(check != 1)
	{
		JLog(@"RSA_check_key() failed with result %lu!", check);
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		return nil;
	}

	NSData	*sha1Data = [self sha1DataNoKey];
	uint8_t	signature[2048];
	unsigned int	signaturelength	= sizeof(signature);
	
	if( 1 != RSA_sign(NID_sha1, [sha1Data bytes],(int)[sha1Data length], signature, &signaturelength, privateRSA) )
	{
		JLog(@"RSA_sign() failed!");
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		return nil;
	}

	if(signaturelength < 1)
	{
		JLog(@"RSA_sign error");
		RSA_free(privateRSA);
		BIO_free(privateBIO);
		return nil;
	}

	RSA_free(privateRSA);
	BIO_free(privateBIO);

	NSData	*decryptedData = [NSData dataWithBytes:signature length:signaturelength];
	
	return decryptedData;
}



- (BOOL)verifyRSASignature:(NSData *)signatureData withPublicKey:(NSData *)publicKeyData;
{
	if( publicKeyData == nil)
	{
		return NO;
	}

	BIO *publicBIO = NULL;
	RSA *publicRSA = NULL;

	if(!(publicBIO = BIO_new_mem_buf((unsigned char*)[publicKeyData bytes], (int) [publicKeyData length])))
	{
		JLog(@"BIO_new_mem_buf() failed!");
		return NO;
	}

	if(!PEM_read_bio_RSAPublicKey(publicBIO, &publicRSA, NULL, NULL))
	{
		JLog(@"PEM_read_bio_RSAPublicKey() failed!");
		return NO;
	}
	NSData	*sha1Data = [self sha1DataNoKey];

	if( ! RSA_verify(NID_sha1, [sha1Data bytes], (int)[sha1Data length], (void*)[signatureData bytes], (int)[signatureData length], publicRSA) )
	{
		JLog(@"RSA_verify failed!");
		if (publicRSA) RSA_free(publicRSA);
		if (publicBIO) BIO_free(publicBIO);
		return NO;
	}
	if (publicRSA) RSA_free(publicRSA);
	if (publicBIO) BIO_free(publicBIO);

	return YES;
}

#pragma mark old methods

-(NSData *)RSAencryptWithPublicKey:(NSString *)publicKeyString padding:(int)padding
{
	DJLog(@"%@",[self description]);
	
	RSA *newRSA = NULL;
	BIO *publickeymemory  = BIO_new_mem_buf((void *)[publicKeyString UTF8String], (int) [publicKeyString lengthOfBytesUsingEncoding:NSUTF8StringEncoding] );
	
	if( NULL == publickeymemory )
	{
		JLog(@"couldn't create bignum");
		return nil;
	}
	(void)BIO_reset(publickeymemory);
	
	PEM_read_bio_RSAPublicKey(publickeymemory,&newRSA,0,NULL);
	if( NULL == newRSA )
	{
		(void)BIO_reset(publickeymemory);
		PEM_read_bio_RSA_PUBKEY(publickeymemory,&newRSA,0,NULL);
		if( NULL == newRSA )
		{
			JLog(@"couldn't create rsa object");
			return nil;
		}
	}
	
	
	NSMutableData *completeData = [NSMutableData data];
	
	unsigned int	currentposition		= 0;
	unsigned int	encryptedpadding	= 0;//RSA_size(newRSA) - 11;

	switch( padding )
	{
		case	RSA_PKCS1_PADDING:			encryptedpadding = RSA_size(newRSA) - 11; break;
		case	RSA_PKCS1_OAEP_PADDING:		encryptedpadding = RSA_size(newRSA) - 41; break;
		case	RSA_SSLV23_PADDING:			encryptedpadding = RSA_size(newRSA) - 11; break;
		default:							encryptedpadding = INT32_MAX;
	}
	
	NSMutableData	*encryptedData		= [NSMutableData dataWithLength:RSA_size(newRSA)];
	while( currentposition < [self length] )
	{
		int length = RSA_public_encrypt( (int) (([self length] - currentposition)%encryptedpadding), [self bytes]+currentposition ,(unsigned char *)[encryptedData bytes], newRSA, padding);
		if( 0 == length )
		{
			JLog(@"Encryption error");
			return nil;
		}
		
		[completeData appendData:[NSData dataWithBytesNoCopy:(unsigned char *)[encryptedData bytes] length:length freeWhenDone:NO]];
		currentposition += encryptedpadding;
	}
	DJLog(@"encrypted Data:%@",[completeData description]);
	return (NSData *)completeData;
}
static int verify_ripemd160(unsigned char *msg, unsigned int mlen, unsigned char *sig, unsigned int siglen, RSA *r);
static int verify_ripemd160(unsigned char *msg, unsigned int mlen, unsigned char *sig, unsigned int siglen, RSA *r) 
{
  unsigned char hash[20];
  BN_CTX        *c;
  int           ret;

  if (!(c = BN_CTX_new())) return 0;
  if (!RIPEMD160(msg, mlen, hash) || !RSA_blinding_on(r, c)) {
    BN_CTX_free(c);
    return 0;
  }
  ret = RSA_verify(NID_ripemd160, hash, 20, sig, siglen, r);
  RSA_blinding_off(r);
  BN_CTX_free(c);
  return ret;
}
static int verify_ripemd160(unsigned char *msg, unsigned int mlen, unsigned char *sig, unsigned int siglen, RSA *r);
static int verify_sha1(unsigned char *msg, unsigned int mlen, unsigned char *sig, unsigned int siglen, RSA *r) 
{
  unsigned char hash[20];
  BN_CTX        *c;
  int           ret;

  if (!(c = BN_CTX_new())) return 0;
  if (!SHA1(msg, mlen, hash) || !RSA_blinding_on(r, c)) {
    BN_CTX_free(c);
    return 0;
  }
  ret = RSA_verify(NID_sha1, hash, 20, sig, siglen, r);
  RSA_blinding_off(r);
  BN_CTX_free(c);
  return ret;
}


- (bool)		RSAcheckSignature:(NSData *)signature withPublicKey:(NSString *)publicKeyString type:(int)type
{
	DJLog(@"%@",[self description]);
	
	RSA *newRSA = NULL;
	BIO *publickeymemory  = BIO_new_mem_buf((void *)[publicKeyString UTF8String], (int)[publicKeyString lengthOfBytesUsingEncoding:NSUTF8StringEncoding] );
	
	if( NULL == publickeymemory )
	{
		JLog(@"couldn't create bignum");
		return NO;
	}
	(void)BIO_reset(publickeymemory);
	
	PEM_read_bio_RSAPublicKey(publickeymemory,&newRSA,0,NULL);
	if( NULL == newRSA )
	{
		(void)BIO_reset(publickeymemory);
		PEM_read_bio_RSA_PUBKEY(publickeymemory,&newRSA,0,NULL);
		if( NULL == newRSA )
		{
			JLog(@"couldn't create rsa object");
			BIO_free(publickeymemory);
			return nil;
		}
	}
	BIO_free(publickeymemory);
	
	switch( type )
	{
		case NID_ripemd160:	{
								if( 1 == verify_ripemd160( (unsigned char *)[self bytes], (unsigned int)[self length],(unsigned char *)[signature bytes],(unsigned int) [signature length],newRSA) )
								{
									RSA_free(newRSA);
									return YES;
								}
							}break;
		case NID_sha1:		{
								if( 1 == verify_sha1( (unsigned char *)[self bytes], (unsigned int)[self length],(unsigned char *)[signature bytes], (unsigned int)[signature length],newRSA) )
								{
									RSA_free(newRSA);
									return YES;
								}
						}break;
		default:		JLog(@"type %d not supported.",type);
						RSA_free(newRSA);

	}
	DJLog(@"signature did not match");
	return NO;
}



@end

