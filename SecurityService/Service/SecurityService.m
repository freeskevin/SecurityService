//
//  SecurityService.m
//  UpgradeModule
//
//  Created by Kevin on 2022/6/27.
//

#import "SecurityService.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation SecurityService


+ (NSString *)aes256_encrypt:(NSString *)key originString:(NSString *)oriString
{
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    const char *cstr = [oriString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *oriData = [NSData dataWithBytes:cstr length:oriString.length];
    NSUInteger dataLength = [oriData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCBlockSizeAES128, NULL, [oriData bytes], dataLength, buffer, bufferSize, &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        
        NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        
        if (data && data.length > 0) {
            
            Byte *datas = (Byte*)[data bytes];
            NSMutableString *output = [NSMutableString stringWithCapacity:data.length * 2];
            for(int i = 0; i < data.length; i++){
                [output appendFormat:@"%02x", datas[i]];
            }
            return output;
        }
        return nil;
    }
    
    free(buffer);
    return nil;
}


+ (NSString *)aes256_decrypt:(NSString *)key enString:(NSString *)enString
{
    
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSMutableData *enData = [NSMutableData dataWithCapacity:enString.length / 2];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < [enString length] / 2; i++) {
        byte_chars[0] = [enString characterAtIndex:i*2];
        byte_chars[1] = [enString characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [enData appendBytes:&whole_byte length:1];
    }
    
    NSUInteger dataLength = [enData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeAES128,
                                          NULL,
                                          [enData bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        if (data && data.length > 0) {
            return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        }
        return nil;
    }
    free(buffer);
    return nil;
}

+ (NSString *)obfuscate:(NSString *)oriString
{
    char *str = malloc(oriString.length);
    for (int i = 0; i < oriString.length; i++) {
        NSString *transferString = [oriString substringWithRange:NSMakeRange(i, 1)];
        const char *c = [transferString cStringUsingEncoding:NSUTF8StringEncoding];
        char dc = c[0] + 1;
        str[i] = dc;
    }
    NSString *resStr = [[NSString alloc] initWithFormat:@"%s", str];
    free(str);
    return resStr;
}



@end
