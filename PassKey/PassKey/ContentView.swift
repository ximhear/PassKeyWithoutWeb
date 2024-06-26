import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = AuthViewModel()

    var body: some View {
        VStack(spacing: 20) {
            if viewModel.isAuthenticated {
                Text("Welcome, authenticated user!")
                    .font(.largeTitle)
                    .padding()
            } else {
                Text("Please authenticate")
                    .font(.title)
                if let userID = viewModel.userID {
                    Text("User ID: \(userID)")
                        .padding()
                }
                
                Button(action: {
                    viewModel.generateKeyPair()
                    viewModel.registerPublicKey()
                }) {
                    Text("Register")
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                }
                
                Button(action: {
                    viewModel.login1()
                }) {
                    Text("Login In without Auth Framework")
                        .padding()
                        .background(Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                }
                Button(action: {
                    viewModel.startSignInWithPasskey()
                }) {
                    Text("Sign In")
                        .padding()
                        .background(Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                }
                
                if let message = viewModel.message {
                    Text(message)
                        .foregroundColor(.red)
                        .padding()
                }
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
