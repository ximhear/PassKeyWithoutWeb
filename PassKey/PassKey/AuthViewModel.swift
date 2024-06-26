import Foundation
import AuthenticationServices
import SwiftUI
import CommonCrypto

class AuthViewModel: NSObject, ObservableObject, ASAuthorizationControllerDelegate {
    @Published var isAuthenticated = false
    @Published var message: String?
    
    let apiUrl = "https://ccd0-165-243-5-20.ngrok-free.app"
    
    var publicKey: SecKey?
    var privateKey: SecKey?
    @Published var userID: String?
    
    override init() {
        super.init()
        loadKeysAndUserID()
    }
    
    func login1() {
        guard let userID else {
            return
        }
        let url = URL(string: apiUrl + "/login-challenge")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        let params: [String: Any] = ["username": "testuser", "userid": userID]
        request.httpBody = try? JSONSerialization.data(withJSONObject: params, options: [])
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Error: \(error!)")
                return
            }
            
            if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let challenge = jsonResponse["challenge"] as? String {
                print("Received Challenge: \(challenge)")
                self.signChallenge1(challenge: challenge)
            }
        }
        task.resume()
    }
    
    func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
 
    func signChallenge1(challenge: String) {
        guard let userID else {
            return
        }
        guard let privateKey else { return }
        guard let publicKey else { return }
        
        guard let challengeData = Data(base64Encoded: challenge) else { return }
        // 해시 생성
        let digest = sha256(data: challengeData)
        digest.printHex()
        GZLogFunc(digest.base64EncodedString())
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureDigestPKCS1v15SHA256, digest as CFData, &error) else {
            print("Error signing challenge: \(error!.takeRetainedValue() as Error)")
            return
        }
       
        /*
        // SHA-256 해시 생성 함수
        guard SecKeyVerifySignature(publicKey, .rsaSignatureDigestPKCS1v15SHA256, digest as CFData, signature as CFData, &error) else {
            GZLogFunc()
            return
        }
        GZLogFunc()
         */
        
        let signedChallenge = (signature as Data).base64EncodedString()
        print("Signed Challenge: \(signedChallenge)")
        let params: [String: Any] = [
            "username": "testuser",
            "userid": userID,
            "challenge": challenge,
            "signed_challenge": signedChallenge
        ]
        
        let url = URL(string: apiUrl + "/verify1")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: params, options: [])
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Error: \(error!)")
                return
            }
            print("Server Response: \(String(data: data, encoding: .utf8)!)")
        }
        task.resume()
    }
    
    func generateKeyPair() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]

        var error: Unmanaged<CFError>?
        privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        guard let privateKey = privateKey else {
            message = "Error generating private key: \(error!.takeRetainedValue() as Error)"
            return
        }
        publicKey = SecKeyCopyPublicKey(privateKey)

        if let publicKey = publicKey, let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data {
            KeychainHelper.shared.save(key: "publicKey", data: publicKeyData)
            GZLogFunc(publicKeyData.base64EncodedString())
            GZLogFunc()
            
        }

        if let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as? Data {
            KeychainHelper.shared.save(key: "privateKey", data: privateKeyData)
            GZLogFunc(privateKeyData.base64EncodedString())
            GZLogFunc()
        }
    }
    
    func registerPublicKey() {
        guard let publicKey = publicKey else { return }
        
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            message = "Error exporting public key: \(error!.takeRetainedValue() as Error)"
            return
        }
        
        let publicKeyBase64 = (publicKeyData as Data).base64EncodedString()
        GZLogFunc("Public Key (base64): \(publicKeyBase64)")
        let params: [String: Any] = [
            "username": "testuser",
            "public_key": publicKeyBase64
        ]
        
        guard let url = URL(string: apiUrl + "/register") else {
            message = "Invalid server URL"
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: params, options: [])
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                DispatchQueue.main.async {
                    self.message = "Error: \(error.localizedDescription)"
                }
                return
            }
            guard let data = data,
                  let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                  let userID = jsonResponse["userID"] as? String else {
                DispatchQueue.main.async {
                    self.message = "Invalid response from server"
                }
                return
            }
            self.userID = userID
            KeychainHelper.shared.save(key: "userID", data: userID.data(using: .utf8)!)
            DispatchQueue.main.async {
                self.message = "Registered successfully with userID: \(userID)"
            }
        }
        task.resume()
    }
    
    func loadKeysAndUserID() {
        if let publicKeyData = KeychainHelper.shared.load(key: "publicKey"),
           let privateKeyData = KeychainHelper.shared.load(key: "privateKey") {
            var error: Unmanaged<CFError>?
            publicKey = SecKeyCreateWithData(publicKeyData as CFData, [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 2048
            ] as CFDictionary, &error)

            privateKey = SecKeyCreateWithData(privateKeyData as CFData, [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048
            ] as CFDictionary, &error)
        }

        if let userIDData = KeychainHelper.shared.load(key: "userID") {
            userID = String(data: userIDData, encoding: .utf8)
        }
    }
    
    func startSignInWithPasskey() {
        guard let userID = userID else {
            message = "UserID not found"
            return
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "ccd0-165-243-5-20.ngrok-free.app")
        let request = provider.createCredentialAssertionRequest(challenge: Data())
        
        let authController = ASAuthorizationController(authorizationRequests: [request])
        authController.delegate = self
        authController.performRequests()
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion,
           let authenticatorData = credential.rawAuthenticatorData,
           let signature = credential.signature,
           let userID = credential.userID {
            let clientDataJSON = credential.rawClientDataJSON
            sendAssertionToServer(clientDataJSON: clientDataJSON, authenticatorData: authenticatorData, signature: signature, userID: userID)
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        DispatchQueue.main.async {
            self.message = "Authorization failed: \(error.localizedDescription)"
        }
    }
    
    func sendAssertionToServer(clientDataJSON: Data, authenticatorData: Data, signature: Data, userID: Data) {
        guard let url = URL(string: apiUrl + "/verify") else {
            message = "Invalid server URL"
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let params: [String: Any] = [
            "clientDataJSON": clientDataJSON.base64EncodedString(),
            "authenticatorData": authenticatorData.base64EncodedString(),
            "signature": signature.base64EncodedString(),
            "userID": userID.base64EncodedString()
        ]
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonData
        } catch {
            message = "Error serializing JSON: \(error)"
            return
        }
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                DispatchQueue.main.async {
                    self.message = "Error sending request: \(error.localizedDescription)"
                }
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                DispatchQueue.main.async {
                    self.message = "Invalid response from server"
                }
                return
            }
            
            DispatchQueue.main.async {
                if httpResponse.statusCode == 200 {
                    self.isAuthenticated = true
                    self.message = "Successfully authenticated"
                } else {
                    self.message = "Authentication failed with status code: \(httpResponse.statusCode)"
                }
            }
        }
        
        task.resume()
    }
    
    func verifySignature(challenge: String) {

        var error: Unmanaged<CFError>?

        guard let privateKey,
              let publicKey else {
            print("Error creating keys from data: \(error!.takeRetainedValue() as Error)")
            return
        }

        guard let challengeData = Data(base64Encoded: challenge) else {
            print("Challenge data decoding failed")
            return
        }

        // 해시 생성
        let digest = sha256(data: challengeData)
        
        // 서명 생성 (해시된 데이터 사용)
        guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureDigestPKCS1v15SHA256, digest as CFData, &error) else {
            print("Error signing challenge: \(error!.takeRetainedValue() as Error)")
            return
        }

        // 서명 데이터 출력
        let signatureData = signature as Data
        print("Signature Data: \(signatureData.base64EncodedString())")

        // 서명 검증
        guard SecKeyVerifySignature(publicKey, .rsaSignatureDigestPKCS1v15SHA256, digest as CFData, signature as CFData, &error) else {
            if let error = error {
                print("Error verifying signature: \(error.takeRetainedValue() as Error)")
            } else {
                print("Unknown error verifying signature")
            }
            return
        }

        print("Signature verification succeeded")
    }
}

extension Data {
    func printHex() {
        print("Data Length: \(count)")
        for byte in self {
            print(String(format: "%02x", byte), terminator: ",")
        }
        print()
    }
}
