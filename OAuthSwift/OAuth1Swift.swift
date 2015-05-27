//
//  OAuth1Swift.swift
//  OAuthSwift
//
//  Created by Dongri Jin on 6/22/14.
//  Copyright (c) 2014 Dongri Jin. All rights reserved.
//

import Foundation
import UIKit

// OAuthSwift errors
public let OAuthSwiftErrorDomain = "oauthswift.error"

public class OAuth1Swift: NSObject {

    public var client: OAuthSwiftClient

    public var webViewController: UIViewController?

    public var consumer_key: String
    public var consumer_secret: String
    public var request_token_url: String
    public var authorize_url: String
    public var access_token_url: String

    var observer: AnyObject?

    public init(consumerKey: String, consumerSecret: String, requestTokenUrl: String, authorizeUrl: String, accessTokenUrl: String){
        self.consumer_key = consumerKey
        self.consumer_secret = consumerSecret
        self.request_token_url = requestTokenUrl
        self.authorize_url = authorizeUrl
        self.access_token_url = accessTokenUrl
        self.client = OAuthSwiftClient(consumerKey: consumerKey, consumerSecret: consumerSecret)
    }

    struct CallbackNotification {
        static let notificationName = "OAuthSwiftCallbackNotificationName"
        static let optionsURLKey = "OAuthSwiftCallbackNotificationOptionsURLKey"
    }

    struct OAuthSwiftError {
        static let domain = "OAuthSwiftErrorDomain"
        static let appOnlyAuthenticationErrorCode = 1
    }

    public typealias TokenSuccessHandler = (credential: OAuthSwiftCredential, response: NSURLResponse) -> Void
    public typealias FailureHandler = (error: NSError) -> Void

    // 0. Start
    public func authorizeWithCallbackURL(callbackURL: NSURL, success: TokenSuccessHandler, failure: ((error: NSError) -> Void)) {
        self.postOAuthRequestTokenWithCallbackURL(callbackURL, success: { credential, response in
            self.setupCallBackObserver(success, failure: failure)
            // 2. Authorize
            let queryURL = NSURL(string: self.authorize_url + "?oauth_token=\(credential.oauth_token)")
            if ( self.webViewController != nil ) {
                if let webView = self.webViewController as? WebViewProtocol {
                    webView.setUrl(queryURL!)
                    UIApplication.sharedApplication().topViewController()!.presentViewController(
                        self.webViewController!, animated: true, completion: nil)
                }
            } else {
                UIApplication.sharedApplication().openURL(queryURL!)
            }
            }, failure: failure)
    }


    func setupCallBackObserver(success: TokenSuccessHandler, failure: FailureHandler) {
        self.observer = NSNotificationCenter.defaultCenter().addObserverForName(CallbackNotification.notificationName, object: nil, queue: NSOperationQueue.mainQueue(), usingBlock:{
            notification in
            //NSNotificationCenter.defaultCenter().removeObserver(self)
            NSNotificationCenter.defaultCenter().removeObserver(self.observer!)
            let url = notification.userInfo![CallbackNotification.optionsURLKey] as! NSURL
            if let query = url.query {
                let parameters = query.parametersFromQueryString()
                if (parameters["oauth_token"] != nil && parameters["oauth_verifier"] != nil) {
                    var credential: OAuthSwiftCredential = self.client.credential
                    self.client.credential.oauth_token = parameters["oauth_token"]!
                    self.client.credential.oauth_verifier = parameters["oauth_verifier"]!
                    self.postOAuthAccessTokenWithRequestToken({
                        credential, response in
                        success(credential: credential, response: response)
                        }, failure: failure)
                    return
                }
            }
            let userInfo = [NSLocalizedFailureReasonErrorKey: NSLocalizedString("Oauth problem.", comment: "")]
            failure(error: NSError(domain: OAuthSwiftErrorDomain, code: -1, userInfo: userInfo))
            return
        })
    }


    // 1. Request token
    public func postOAuthRequestTokenWithCallbackURL(callbackURL: NSURL, success: TokenSuccessHandler, failure: FailureHandler?) {
        var parameters =  Dictionary<String, AnyObject>()
        if let callbackURLString = callbackURL.absoluteString {
            parameters["oauth_callback"] = callbackURLString
        }
        let reqURL = self.request_token_url
        self.client.post(reqURL, parameters: parameters, success: {
            data, response in
            self.handleRequestTokenResponse(data, response: response, success: success, failure: failure)
            }, failure: failure)
    }

    public func handleRequestTokenResponse(data: NSData, response: NSHTTPURLResponse, success: TokenSuccessHandler, failure: FailureHandler?) {
        let responseString = NSString(data: data, encoding: NSUTF8StringEncoding) as! String
        let parameters = responseString.parametersFromQueryString()
        self.client.credential.oauth_token = parameters["oauth_token"]!
        self.client.credential.oauth_token_secret = parameters["oauth_token_secret"]!
        success(credential: self.client.credential, response: response)
    }

    // 3. Get Access token
    public func postOAuthAccessTokenWithRequestToken(success: TokenSuccessHandler, failure: FailureHandler?) {
        var parameters = Dictionary<String, AnyObject>()
        parameters["oauth_token"] = self.client.credential.oauth_token
        parameters["oauth_verifier"] = self.client.credential.oauth_verifier
        self.client.post(self.access_token_url, parameters: parameters, success: {
            data, response in
            self.handleAccessTokenResponseData(data, response: response, success: success, failure: failure)
            }, failure: failure)
    }

    public func handleAccessTokenResponseData(data: NSData, response: NSHTTPURLResponse, success: TokenSuccessHandler, failure: FailureHandler?) {
        let responseString = NSString(data: data, encoding: NSUTF8StringEncoding) as! String
        let parameters = responseString.parametersFromQueryString()
        self.client.credential.oauth_token = parameters["oauth_token"]!
        self.client.credential.oauth_token_secret = parameters["oauth_token_secret"]!
        self.handleAccessTokenReceived(self.client.credential)
        success(credential: self.client.credential, response: response)
    }

    public class func handleOpenURL(url: NSURL) {
        let notification = NSNotification(name: CallbackNotification.notificationName, object: nil,
            userInfo: [CallbackNotification.optionsURLKey: url])
        NSNotificationCenter.defaultCenter().postNotification(notification)
    }

    public func handleAccessTokenReceived(credential: OAuthSwiftCredential) {

    }

}

extension UIApplication {
    func topViewController(base: UIViewController? = UIApplication.sharedApplication().keyWindow?.rootViewController) -> UIViewController? {
        if let nav = base as? UINavigationController {
            return topViewController(base: nav.visibleViewController)
        }
        if let tab = base as? UITabBarController {
            if let selected = tab.selectedViewController {
                return topViewController(base: selected)
            }
        }
        if let presented = base?.presentedViewController {
            return topViewController(base: presented)
        }
        return base
    }
}
