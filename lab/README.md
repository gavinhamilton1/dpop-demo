# DPoP Hands-On Lab: Browser Identity & Security

## 🎯 Learning Objectives

By the end of this 30-minute lab, participants will understand and implement:

1. **Browser Identity Key (BIK) Registration** - Creating non-exportable cryptographic keys
2. **DPoP (Demonstration of Proof-of-Possession) Binding** - Cryptographically binding browser identity to session tokens
3. **WebAuthn/Passkey Integration** - Passwordless authentication with device biometrics
4. **Cross-Device Linking** - Secure device-to-device communication
5. **Session Management** - Secure session restoration and state management

## 📋 Prerequisites

- Basic JavaScript knowledge
- Understanding of web security concepts (CSRF, authentication)
- Modern browser (Chrome, Firefox, Safari, Edge)
- Code editor (VS Code recommended)

## 🏗️ Lab Structure

### Part 1: Setup & Application (5 minutes)
- Clone the lab repository
- Understand the project structure
- Run the basic application

### Part 2: Core Implementation (20 minutes)
- **Step 1**: Implement BIK registration (5 min)
- **Step 2**: Implement DPoP binding (5 min)  
- **Step 3**: Test API with DPoP (5 min)
- **Step 4**: Add WebAuthn passkey support (5 min)
- **Step 5**: Implement cross-device linking (5 min)

### Part 3: Testing & Validation (5 minutes)
- Test the complete flow
- Verify security properties
- Discuss real-world applications

## 🎓 Key Concepts Covered

### Browser Identity Key (BIK)
- **What**: Non-exportable cryptographic key pair stored in browser
- **Why**: Establishes unique browser identity for security operations
- **How**: Web Crypto API for key generation and storage

### DPoP (Demonstration of Proof-of-Possession)
- **What**: Cryptographic proof that client possesses a specific key
- **Why**: Prevents token theft and replay attacks
- **How**: JWS (JSON Web Signature) with specific headers and claims

### WebAuthn/Passkeys
- **What**: Standard for passwordless authentication
- **Why**: Eliminates password vulnerabilities, uses device biometrics
- **How**: Public key cryptography with user verification

### Cross-Device Linking
- **What**: Secure communication between devices
- **Why**: Enables VDI environments and step-up authentication
- **How**: QR codes, WebSockets, and cryptographic verification

## 🔧 Technical Stack

- **Frontend**: Vanilla JavaScript, Web Crypto API, WebAuthn
- **Backend**: FastAPI (Python), JWT, cryptographic operations
- **Storage**: IndexedDB for client-side key storage
- **Communication**: WebSockets for real-time device linking

## 📚 Additional Resources

- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## 🎯 Success Criteria

Participants will successfully:
- ✅ Generate and store browser identity keys
- ✅ Create DPoP proofs for API requests
- ✅ Implement passkey registration and authentication
- ✅ Establish secure cross-device communication
- ✅ Understand the security benefits of each component

## 🚀 Next Steps

After completing this lab, participants can:
- Apply these concepts to their own applications
- Implement additional security controls
- Explore advanced DPoP features (nonce challenges, token binding)
- Integrate with enterprise identity systems
