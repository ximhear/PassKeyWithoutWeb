import SwiftUI
import AuthenticationServices
import Combine

class ContentViewModel: NSObject, ObservableObject, ASAuthorizationControllerDelegate {
    @Published var userId: String = "gzonelee"
    @Published var errorMessage: String?

    private var cancellables = Set<AnyCancellable>()

    func startRegistration() {
        guard let url = URL(string: "http://192.168.0.34/register/begin") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(["userId": userId])

        URLSession.shared.dataTaskPublisher(for: request)
            .map { $0.data }
            .decode(type: PublicKeyCredentialCreationOptions.self, decoder: JSONDecoder())
            .sink(receiveCompletion: { completion in
                if case .failure(let error) = completion {
                    DispatchQueue.main.async {
                        self.errorMessage = "Failed to start registration: \(error.localizedDescription)"
                    }
                }
            }, receiveValue: { options in
                DispatchQueue.main.async {
                    self.performRegistration(with: options)
                }
            })
            .store(in: &cancellables)
    }

    private func performRegistration(with options: PublicKeyCredentialCreationOptions) {
        guard let userIdData = options.user.id.data(using: .utf8) else {
            self.errorMessage = "Invalid user ID format"
            return
        }
        
        guard let challengeData = base64UrlDecode(options.challenge) else {
            self.errorMessage = "Invalid challenge format"
            return
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rp.id)
        let authRequest = provider.createCredentialRegistrationRequest(
            challenge: challengeData,
            name: options.user.name,
            userID: userIdData
        )

        let controller = ASAuthorizationController(authorizationRequests: [authRequest])
        controller.delegate = self
        controller.performRequests()
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let clientData = credential.rawClientDataJSON
            let attestationObject = credential.rawAttestationObject

            guard let url = URL(string: "http://192.168.0.34/register/complete") else { return }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")

            let response: [String: Any] = [
                "userId": userId,
                "response": [
                    "clientDataJSON": clientData.base64EncodedString(),
                    "attestationObject": attestationObject?.base64EncodedString()
                ]
            ]

            request.httpBody = try? JSONSerialization.data(withJSONObject: response, options: [])

            URLSession.shared.dataTaskPublisher(for: request)
                .sink(receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        DispatchQueue.main.async {
                            self.errorMessage = "Failed to complete registration: \(error.localizedDescription)"
                        }
                    }
                }, receiveValue: { _ in
                    DispatchQueue.main.async {
                        self.errorMessage = nil
                    }
                })
                .store(in: &cancellables)
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        DispatchQueue.main.async {
            GZLogFunc(error.localizedDescription)
            self.errorMessage = "Authorization failed: \(error.localizedDescription)"
        }
    }
}
