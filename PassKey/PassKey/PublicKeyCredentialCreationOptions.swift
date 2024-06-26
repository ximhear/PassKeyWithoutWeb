import Foundation

struct PublicKeyCredentialCreationOptions: Codable {
    struct User: Codable {
        let id: String
        let name: String
        let displayName: String
    }

    struct RelyingParty: Codable {
        let id: String
        let name: String
    }

    struct PubKeyCredParams: Codable {
        let type: String
        let alg: Int
    }

    let rp: RelyingParty
    let user: User
    let challenge: String
    let pubKeyCredParams: [PubKeyCredParams]
    let timeout: Int?
    let excludeCredentials: [ExcludeCredential]?
    let authenticatorSelection: AuthenticatorSelection?
    let attestation: String?

    struct ExcludeCredential: Codable {
        let type: String
        let id: String
    }

    struct AuthenticatorSelection: Codable {
        let authenticatorAttachment: String?
        let requireResidentKey: Bool?
        let userVerification: String?
    }
}
