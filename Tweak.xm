// Tweak.xm - Network Recon
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>

// ==========================================
// HOOK NSURLSession - Bắt request/response
// ==========================================
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    
    NSString *url = request.URL.absoluteString;
    NSString *method = request.HTTPMethod;
    NSData *body = request.HTTPBody;
    
    NSLog(@"[NET-RECON] ═══════════════════════════");
    NSLog(@"[NET-RECON] %@ %@", method, url);
    
    // Log headers nghi vấn
    NSDictionary *headers = request.allHTTPHeaderFields;
    for (NSString *key in headers) {
        NSString *value = headers[key];
        NSString *kl = key.lowercaseString;
        if ([kl containsString:@"device"] ||
            [kl containsString:@"x-"] ||
            [kl containsString:@"cookie"] ||
            [kl containsString:@"user-agent"] ||
            [kl containsString:@"sign"] ||
            [kl containsString:@"token"] ||
            [kl containsString:@"security"]) {
            NSLog(@"[NET-RECON] HEADER %@: %@", key, value);
        }
    }
    
    // Log body nếu là JSON và có từ khóa nghi vấn
    if (body) {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyStr) {
            NSString *lower = bodyStr.lowercaseString;
            if ([lower containsString:@"jailbreak"] ||
                [lower containsString:@"root"]      ||
                [lower containsString:@"device"]    ||
                [lower containsString:@"security"]  ||
                [lower containsString:@"risk"]      ||
                [lower containsString:@"check"]     ||
                [lower containsString:@"sign"]      ||
                [lower containsString:@"uuid"]      ||
                [lower containsString:@"idfa"]) {
                NSLog(@"[NET-RECON] BODY: %@", bodyStr);
            }
        }
    }
    
    // Bọc completion handler để log response
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        NSLog(@"[NET-RECON] RESPONSE %ld %@", (long)httpResp.statusCode, url);
        
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr) {
                NSString *lower = respStr.lowercaseString;
                if ([lower containsString:@"jailbreak"] ||
                    [lower containsString:@"jb"]          ||
                    [lower containsString:@"root"]        ||
                    [lower containsString:@"block"]       ||
                    [lower containsString:@"ban"]         ||
                    [lower containsString:@"risk"]        ||
                    [lower containsString:@"security"]    ||
                    [lower containsString:@"forbidden"]) {
                    NSLog(@"[NET-RECON] ⚠️ RESPONSE BODY: %@", respStr);
                }
            }
        }
        
        if (completionHandler) completionHandler(data, response, error);
    };
    
    return %orig(request, wrappedHandler);
}
%end

// ==========================================
// HOOK NSURLConnection (cho các app cũ)
// ==========================================
%hook NSURLConnection
+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    NSLog(@"[NET-RECON] SYNC %@ %@", request.HTTPMethod, request.URL.absoluteString);
    return %orig;
}
%end

// ==========================================
// HOOK NSUserDefaults - Bắt xem app lưu gì
// ==========================================
%hook NSUserDefaults
- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if (defaultName) {
        NSString *lower = defaultName.lowercaseString;
        if ([lower containsString:@"jailbreak"] ||
            [lower containsString:@"device"]    ||
            [lower containsString:@"uuid"]      ||
            [lower containsString:@"idfa"]      ||
            [lower containsString:@"token"]     ||
            [lower containsString:@"fingerprint"]) {
            NSLog(@"[NET-RECON] NSUserDefaults set %@ = %@", defaultName, value);
        }
    }
    %orig;
}
%end

// ==========================================
// HOOK KEYCHAIN - Bắt xem app lưu gì vào keychain
// ==========================================
%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSDictionary *dict = (__bridge NSDictionary *)attributes;
    NSLog(@"[NET-RECON] SecItemAdd: %@", dict);
    return %orig;
}
