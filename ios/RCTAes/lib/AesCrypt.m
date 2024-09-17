//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//
 
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>
 
#import "AesCrypt.h"
 
@implementation AesCrypt
 
+ (NSString *) toHex:(NSData *)nsdata {
    const unsigned char *bytes = (const unsigned char *)nsdata.bytes;
    NSMutableString *hex = [NSMutableString new];
    for (NSInteger i = 0; i < nsdata.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return [hex copy];
}
 
+ (NSData *)fromHex:(NSString *)string {
    if (!string) {
        return nil;
    }
    
    NSMutableData *data = [NSMutableData dataWithCapacity:string.length / 2];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0', '\0', '\0'};
    int i;
    for (i = 0; i < [string length] / 2; i++) {
        byte_chars[0] = [string characterAtIndex:i * 2];
        byte_chars[1] = [string characterAtIndex:i * 2 + 1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}
 
+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length {
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];
 
    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];
 
    // Key Derivation using PBKDF2 algorithm.
    int status = CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    passwordData.bytes,
                    passwordData.length,
                    saltData.bytes,
                    saltData.length,
                    kCCPRFHmacAlgSHA512,
                    cost,
                    hashKeyData.mutableBytes,
                    hashKeyData.length);
 
    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return @"";
    }
 
    return [self toHex:hashKeyData];
}
 
+ (NSData *)AESCBC:(NSString *)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv algorithm:(NSString *)algorithm {
    if (!data || !key || !iv || !algorithm) {
        return nil;
    }
 
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    if (!keyData || !ivData) {
        return nil;
    }
 
    NSArray *aesAlgorithms = @[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"];
    size_t item = [aesAlgorithms indexOfObject:algorithm];
    size_t keyLength;
    switch (item) {
        case 0:
            keyLength = kCCKeySizeAES128;
            break;
        case 1:
            keyLength = kCCKeySizeAES192;
            break;
        default:
            keyLength = kCCKeySizeAES256;
            break;
    }
 
    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];
    size_t numBytes = 0;
 
    CCCryptorStatus cryptStatus = CCCrypt(
        [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        keyData.bytes, keyLength,
        ivData.length ? ivData.bytes : nil,
        data.bytes, data.length,
        buffer.mutableBytes, buffer.length,
        &numBytes
    );
 
    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
 
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}
 
+ (NSString *)encrypt:(NSString *)clearText key:(NSString *)key iv:(NSString *)iv algorithm:(NSString *)algorithm {
    if (!clearText || !key || !iv || !algorithm) {
        NSLog(@"Encryption failed due to invalid input");
        return nil;
    }
 
    NSData *result = [self AESCBC:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
    if (!result) {
        NSLog(@"Encryption failed");
        return nil;
    }
    
    return [result base64EncodedStringWithOptions:0];
}
 
+ (NSString *)decrypt:(NSString *)cipherText key:(NSString *)key iv:(NSString *)iv algorithm:(NSString *)algorithm {
    if (!cipherText || !key || !iv || !algorithm) {
        return nil;
    }
    
    NSData *result = [self AESCBC:@"decrypt" data:[[NSData alloc] initWithBase64EncodedString:cipherText options:0] key:key iv:iv algorithm:algorithm];
    if (!result) {
        return nil;
    }
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}
 
+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}
 
+ (NSString *) hmac512: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA512, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}
 
+ (NSString *) sha1: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self toHex:result];
}
 
+ (NSString *) sha256: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}
 
+ (NSString *) sha512: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}
 
+ (NSString *) randomUuid {
  return [[NSUUID UUID] UUIDString];
}
 
+ (NSString *) randomKey: (NSInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [self toHex:data];
}
 
 
+ (NSDictionary *)encryptFile:(NSString *)hexKey iv:(NSString *)hexIv hmacKey:(NSString *)hmacKey inputPath:(NSString *)inputPath outputPath:(NSString *)outputPath {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSData *keyData = [[self fromHex:hexKey] copy];
    NSData *ivData = [[self fromHex:hexIv] copy];
    NSData *hmacKeyData = [[self fromHex:hmacKey] copy];
    NSMutableData *streamDigest = [NSMutableData data];
 
    if (![fileManager fileExistsAtPath:inputPath]) {
        NSLog(@"Input file doesn't exist.");
        return nil;
    }
 
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:inputPath];
    NSOutputStream *outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
 
    if (!inputStream || !outputStream) {
        NSLog(@"Failed to open input or output stream.");
        return nil;
    }
 
    [inputStream open];
    [outputStream open];
 
    // Calculate file size
    NSUInteger fileSize = [self getFileSizeAtPath:inputPath];
 
    // Set up cipher for encryption with NoPadding
    CCCryptorRef cryptor;
    CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, 0, keyData.bytes, keyData.length, ivData.bytes, &cryptor);
 
    if (status != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", status);
        [inputStream close];
        [outputStream close];
        return nil;
    }
 
    // Set up MAC
    CCHmacContext hmacContext;
    CCHmacInit(&hmacContext, kCCHmacAlgSHA256, hmacKeyData.bytes, hmacKeyData.length);
 
    NSUInteger bufferSize = 64 * 1024;
    uint8_t *buffer = malloc(bufferSize);
    NSUInteger bytesRead = 0;
    NSUInteger bytesEncrypted = 0;
    NSUInteger totalBytesRead = 0; // Keep track of total bytes read
 
    // Calculate padding size
    BOOL isMultipleOfBlockSize = fileSize % 16 == 0;
    NSUInteger paddingSize = isMultipleOfBlockSize ? 0 : (16 - (fileSize % 16));
 
    // Read data from the input file, encrypt it, and write to the output file
    while ((bytesRead = [inputStream read:buffer maxLength:bufferSize]) > 0) {
        totalBytesRead += bytesRead; // Increment the total bytes read
        // Check if this is the last chunk by comparing total bytes read to file size
        BOOL isLastChunk = (totalBytesRead == fileSize);
    
        if (isLastChunk && paddingSize > 0) {
            // Ensure there's enough space for adding the padding
            if (bytesRead + paddingSize <= bufferSize) {
                for (NSUInteger i = 0; i < paddingSize; i++) {
                    buffer[bytesRead + i] = (int)paddingSize;  // Set each byte to the padding size
                }
                bytesRead += paddingSize;  // Update the number of bytes read to include the padding
            } else {
                NSLog(@"Buffer overflow: Cannot add padding, buffer too small");
                // Handle the case where buffer is too small
            }
        }
        
        
        status = CCCryptorUpdate(cryptor, buffer, bytesRead, buffer, bufferSize, &bytesEncrypted);
        if (status != kCCSuccess) {
            NSLog(@"Failed to encrypt data: %d", status);
            break;
        }
        
        if (bytesEncrypted > 0) {
            [outputStream write:buffer maxLength:bytesEncrypted];
            CCHmacUpdate(&hmacContext, buffer, bytesEncrypted);
            [streamDigest appendBytes:buffer length:bytesEncrypted];
        }
    }
 
    CCCryptorFinal(cryptor, buffer, bufferSize, &bytesEncrypted);
    if (bytesEncrypted > 0) {
        [outputStream write:buffer maxLength:bytesEncrypted];
        CCHmacUpdate(&hmacContext, buffer, bytesEncrypted);
        [streamDigest appendBytes:buffer length:bytesEncrypted];
    }
    
 
    // Generate MAC digest
    uint8_t finalMac[CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&hmacContext, finalMac);
 
    // Append finalMac to streamDigest
    [streamDigest appendBytes:finalMac length:CC_SHA256_DIGEST_LENGTH];
 
    // Convert mac to NSData to add it to file
    NSData *hmacData = [NSData dataWithBytes:finalMac length:CC_SHA256_DIGEST_LENGTH];
    
    // write the hmacData to encrypted file
    [outputStream write:hmacData.bytes maxLength:hmacData.length];
 
    // Do the hashing for the digest
    NSMutableData *digestData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, hmacKeyData.bytes, hmacKeyData.length, streamDigest.bytes, streamDigest.length, digestData.mutableBytes);
    CC_SHA256(streamDigest.bytes, (CC_LONG)streamDigest.length, digestData.mutableBytes);
 
    // Cleanup
    CCCryptorRelease(cryptor);
    free(buffer);
    [inputStream close];
    [outputStream close];
 
    // Create NSDictionary with auth and paddingSize
    NSString *auth = [self toHex:digestData];
    NSDictionary *result = @{
        @"auth": auth,
        @"paddingSize": @(paddingSize)
    };
 
    return result;
}
 
 
+ (void)decryptFile:(NSString *)hexKey iv:(NSString *)hexIv hmacKey:(NSString *)hmacKey digest:(NSString *)digest inputPath:(NSString *)inputPath outputPath:(NSString *)outputPath paddingSize:(NSUInteger)paddingSize completion:(void (^)(NSString *result))completion{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            // Convert hex strings to data
            NSData *keyData = [self fromHex:hexKey];
            NSData *ivData = [self fromHex:hexIv];
            NSData *hmacKeyData = [self fromHex:hmacKey];
            NSData *expectedDigestData = [self fromHex:digest];
            
            // Get the size of the input file
            NSUInteger fileSize =[self getFileSizeAtPath:inputPath];
            if (expectedDigestData == nil) {
                NSLog(@"Missing digest!");
                @throw [NSException exceptionWithName:NSGenericException reason:@"Missing digest!" userInfo:nil];
            }
            
            NSFileManager *fileManager = [NSFileManager defaultManager];
            
            if (![fileManager fileExistsAtPath:inputPath]) {
                NSLog(@"Input file doesn't exist.");
                @throw [NSException exceptionWithName:NSGenericException reason:@"Input file doesn't exist." userInfo:nil];
            }
            
            NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:inputPath];
            NSOutputStream *outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
            
            if (!inputStream || !outputStream) {
                NSLog(@"Failed to open input or output stream.");
                @throw [NSException exceptionWithName:NSGenericException reason:@"Failed to open input or output stream." userInfo:nil];
            }
            
            // Open input streams
            [inputStream open];
            [outputStream open];
            
            
            // Set up cipher
            CCCryptorRef cryptor;
            CCCryptorStatus status = CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, 0, keyData.bytes, keyData.length, ivData.bytes, &cryptor);
            
            if (status != kCCSuccess) {
                NSLog(@"Failed to create cryptor: %d", status);
                [inputStream close];
                [outputStream close];
                @throw [NSException exceptionWithName:NSGenericException reason:@"Failed to create cryptor" userInfo:nil];
 
            }
            
            // Set up MAC
            CCHmacContext hmacContext;
            CCHmacInit(&hmacContext, kCCHmacAlgSHA256, hmacKeyData.bytes, hmacKeyData.length);
            
            // Set up SHA-256 digest context
            CC_SHA256_CTX sha256Context;
            CC_SHA256_Init(&sha256Context);
            NSMutableData *streamDigest = [NSMutableData data];
            NSInteger chunkSize = 64 * 1024;
            uint8_t buffer[chunkSize];
            // Calculate the remaining data length by subtracting the MAC length from the file length
            double remainingData = fileSize - CC_SHA256_DIGEST_LENGTH;
            NSUInteger bytesWritten = 0;
            // Read and decrypt data from the input file (excluding the MAC portion), and write to the output file
            while (remainingData > 0) {
                
                BOOL isLastChunk = remainingData <= chunkSize;
                NSInteger bytesRead = [inputStream read:buffer maxLength:MIN(sizeof(buffer), remainingData)];
                
                // Update the MAC and stream digest with the read data
                CCHmacUpdate(&hmacContext, buffer, bytesRead);
                [streamDigest appendBytes:buffer length:bytesRead];
                CC_SHA256_Update(&sha256Context, buffer, (CC_LONG)bytesRead);
                
                // Decrypt the data
                CCCryptorUpdate(cryptor, buffer, bytesRead, buffer, sizeof(buffer), &bytesWritten);
                
                // Check if this is the last chunk
                remainingData -= bytesRead;
                
                // Handle padding removal for the last chunk
                if (isLastChunk && paddingSize > 0) {
                    // Calculate the actual length of the last chunk after decryption
                    NSUInteger actualLength = bytesWritten;
                
                    // Truncate the output buffer to remove padding
                    if (actualLength > paddingSize) {
                        [outputStream write:buffer maxLength:actualLength - paddingSize];
                    }
                } else {
                    // Write the decrypted data to the output file
                    [outputStream write:buffer maxLength:bytesWritten];
                }
            }
            
            
            // Calculate our MAC
            unsigned char ourMac[CC_SHA256_DIGEST_LENGTH];
            CCHmacFinal(&hmacContext, ourMac);
            [streamDigest appendBytes:ourMac length:CC_SHA256_DIGEST_LENGTH];
            
            // Read the MAC from the input file
            unsigned char theirMac[CC_SHA256_DIGEST_LENGTH];
            [inputStream read:theirMac maxLength:CC_SHA256_DIGEST_LENGTH];
            
            // Convert MAC data to NSData for comparison
            NSData *ourMacData = [NSData dataWithBytes:ourMac length:CC_SHA256_DIGEST_LENGTH];
            NSData *theirMacData = [NSData dataWithBytes:theirMac length:CC_SHA256_DIGEST_LENGTH];
            
            // Compare our MAC with the received MAC
            if (![ourMacData isEqualToData:theirMacData]) {
                NSLog(@"MAC doesn't match!");
                CCCryptorRelease(cryptor);
                [inputStream close];
                [outputStream close];
                NSError *error;
                [fileManager removeItemAtPath:outputPath error:&error];
                @throw [NSException exceptionWithName:NSGenericException reason:@"MAC doesn't match!" userInfo:nil];
            }
            
            // Calculate our digest and compare with the expected digest
            NSMutableData *ourDigestData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
            CCHmac(kCCHmacAlgSHA256, hmacKeyData.bytes, hmacKeyData.length, streamDigest.bytes, streamDigest.length, ourDigestData.mutableBytes);
            CC_SHA256(streamDigest.bytes, (CC_LONG)streamDigest.length, ourDigestData.mutableBytes);
            
            if (expectedDigestData != nil && ![ourDigestData isEqualToData:expectedDigestData]) {
                NSLog(@"Digest doesn't match!");
                CCCryptorRelease(cryptor);
                [inputStream close];
                [outputStream close];
                NSError *error;
                [fileManager removeItemAtPath:outputPath error:&error];
                @throw [NSException exceptionWithName:NSGenericException reason:@"Digest doesn't match!" userInfo:nil];
            }
            
            // Finalize the decryption process and write any remaining data
            CCCryptorFinal(cryptor, buffer, sizeof(buffer), &bytesWritten);
            if (bytesWritten > 0) {
                [outputStream write:buffer maxLength:bytesWritten];
            }
            
            
            // Cleanup
            CCCryptorRelease(cryptor);
            [inputStream close];
            [outputStream close];
            
            
            completion(@"Success");
        } @catch (NSException *exception) {
            completion(exception.reason);
        }
    });
}
 
 
+ (NSUInteger)getFileSizeAtPath:(NSString *)filePath {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:filePath error:nil];
    NSNumber *fileSize = fileAttributes[NSFileSize];
    return [fileSize unsignedIntegerValue];
}
 
 
@end