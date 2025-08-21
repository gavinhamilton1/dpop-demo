# 🔐 Browser Identity & DPoP Security Reference Implementation

A comprehensive reference implementation demonstrating **browser identity management** using **non-exportable WebCrypto keys** and **DPoP (Demonstration of Proof-of-Possession)** tokens. This project showcases advanced cryptographic security patterns for web applications, including browser-bound identity, cryptographic request signing, and protection against various web security threats.

## 🎯 What This Demonstrates

### **🔐 Browser Identity & Cryptographic Security**
- **Non-exportable WebCrypto keys**: Browser-bound cryptographic identity that cannot be extracted
- **Browser Identity Keys (BIK)**: Unique cryptographic identity per browser session
- **Browser-bound authentication**: Keys tied to specific browser security context
- **Device linking**: Secure device-to-device authentication using QR codes

### **🛡️ DPoP (Demonstration of Proof-of-Possession)**
- **Cryptographic request binding**: Every API request cryptographically signed
- **Client and server signing**: Two-way verification for mutual authentication
- **Replay protection**: Nonce-based request validation prevents replay attacks
- **Cross-origin security**: Secure API access across domains with cryptographic proof
- **Token binding**: Prevents token theft, replay attacks, and unauthorized API access

### **📱 Progressive Web App Features**
- **Service Worker integration**: Background sync and offline capabilities
- **IndexedDB storage**: Client-side secure storage
- **Real-time communication**: Server-Sent Events for live updates

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Desktop       │    │   Mobile        │    │   Server        │
│   Browser       │    │   Browser       │    │   (FastAPI)     │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • WebAuthn      │    │ • WebAuthn      │    │ • DPoP          │
│ • DPoP Binding  │    │ • QR Code Scan  │    │ • Session Mgmt  │
│ • Service Worker│    │ • Cross-device  │    │ • Passkey Auth  │
│ • IndexedDB     │    │   Linking       │    │ • Real-time     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Key Features

### **🔑 Browser Identity & Authentication**
- **Non-exportable key generation**: Create browser-bound cryptographic keys using WebCrypto API
- **Browser Identity Keys (BIK)**: Generate unique cryptographic identity for each browser session
- **Browser-bound verification**: Keys tied to specific browser security context and cannot be exported
- **Secure key storage**: Keys stored in browser's secure key storage, protected from extraction
- **Identity continuity**: Persistent browser recognition across sessions

### **🔗 Device Linking & VDI Support**
- **Corporate VDI Environments**: Enable authentication in virtual desktop environments where WebAuthn/Passkeys are unavailable
- **Step-up Authentication**: Provide additional security verification for sensitive operations
- **QR Code Flow**: Scan QR code to link desktop and mobile sessions
- **Real-time sync**: Instant authentication state synchronization
- **Secure binding**: Cryptographic verification of device ownership
- **Session persistence**: Maintains authentication across devices

### **🛡️ Identity Continuity & ATO Protection**
- **DPoP Token Security**: Each token cryptographically bound to a specific device key pair
- **Request signing**: Every API request cryptographically signed with device identity
- **Replay attack prevention**: Nonce-based request validation prevents request replay
- **Cross-origin security**: Secure API access from any origin with cryptographic proof
- **Token theft prevention**: Tokens cannot be used without the original device's private key
- **Man-in-the-middle protection**: Cryptographic signatures prevent request tampering
- **Account takeover protection**: Comprehensive protection against ATO attack vectors

### **⚡ Progressive Web App**
- **Service Worker**: Background processing and offline capabilities
- **IndexedDB**: Client-side secure data storage
- **Real-time updates**: Server-Sent Events for live status updates
- **Responsive design**: Works seamlessly across all devices

## 🛡️ Security Features

### **Frontend (Client)**
- **Vanilla JavaScript**: Modern ES6+ modules, no frameworks
- **WebCrypto API**: Non-exportable key generation, ECDSA signing, SHA-256 hashing
- **Browser Identity Management**: Browser Identity Keys (BIK) and browser-bound authentication
- **WebAuthn API**: Passkey registration and authentication (additional security layer)
- **Service Workers**: Background processing, request interception, and caching
- **IndexedDB**: Client-side secure data storage
- **Server-Sent Events**: Real-time communication for cross-device linking

### **Backend (Server)**
- **FastAPI**: Modern Python web framework
- **SQLite**: Lightweight database with async support
- **Cryptography**: Python cryptography library
- **JOSE**: JSON Web Signature implementation
- **WebAuthn**: Server-side passkey verification

### **Security Features & Attack Prevention**
- **Non-exportable Keys**: Browser-bound keys cannot be extracted or transferred
- **Browser Identity Binding**: Cryptographic binding to specific browsers
- **DPoP Token Binding**: Cryptographic request binding prevents token theft and replay
- **Two-Way Verification**: Client and server signing for mutual authentication
- **Replay Attack Prevention**: Nonce-based request validation
- **Man-in-the-Middle Protection**: Cryptographic signatures prevent request tampering
- **Identity Continuity**: Persistent browser recognition across sessions
- **ATO Protection**: Account takeover attack vector reduction
- **Device Linking**: Multi-device authentication with cryptographic proof
- **VDI Authentication**: Virtual desktop environment support
- **Step-up Authentication**: Enhanced security verification flows
- **CSRF Protection**: Cross-site request forgery prevention
- **Secure Request Signing**: Cryptographic request integrity

## 📦 Installation & Setup

### **Prerequisites**
- Python 3.8+ with pip
- Modern web browser with WebAuthn support
- Device with biometric authentication or security key

### **Quick Start**

1. **Clone the repository**
   ```bash
   git clone https://github.com/gavinhamilton1/dpop-demo.git
   cd dpop-demo
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the server**
   ```bash
   ./server/run.sh
   ```

4. **Open the demo**
   ```
   http://localhost:8000
   ```

## 🎮 Interactive Demo

The demo page provides a comprehensive walkthrough of the device identity and DPoP security features:

### **🚀 Key Features Section**
- **Device Identity & Browser-Bound Keys**: Non-exportable WebCrypto keys that persist across browser sessions
- **Identity Continuity & ATO Protection**: DPoP tokens with two-way verification for account takeover protection
- **Device Linking & VDI Support**: Corporate VDI authentication and step-up security
- **Advanced Web Security**: Service worker interception, secure headers, and comprehensive validation

### **🎮 Interactive Demo Sequence**
Follow the numbered steps to experience the complete workflow:

1. **Initialize Session** - Create a new browser session
2. **Register Browser Identity** - Generate cryptographic key pair for your browser
3. **Bind DPoP Token** - Cryptographically bind your session to a DPoP token
4. **Test API Access** - Demonstrate secure, cryptographically signed API calls
5. **Register Browser Identity** - Create a WebAuthn passkey for additional security
6. **Authenticate Browser Identity** - Verify identity using the registered passkey
7. **Start Device Linking** - Begin VDI/step-up authentication process

### **🔧 Admin & Testing**
- **Server Flush** - Clear server-side session data
- **Client Flush** - Clear client-side stored data
- **Service Worker Management** - Register/unregister service worker
- **Echo Testing** - Test service worker request interception

### **📝 Activity Log**
Real-time logging of all operations and security events for debugging and demonstration.

## 🔧 Implementation Guide

### **Client-Side Implementation**

#### **1. Browser Identity & DPoP Token Management**
```javascript
// Generate non-exportable browser identity key pair
const deviceKeyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false, // Non-exportable - keys cannot be extracted
  ["sign", "verify"]
);

// Create DPoP token bound to browser identity
const dpopToken = await createDpopToken(deviceKeyPair, {
  htu: "https://api.example.com/endpoint",
  htm: "POST",
  nonce: serverNonce
});
```

#### **2. Browser Identity & WebAuthn Integration**
```javascript
// Register browser-bound passkey (additional security layer)
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: challengeBuffer,
    rp: { name: "Example App", id: "example.com" },
    user: { id: userIdBuffer, name: "user@example.com" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: "platform", // Device-bound
      userVerification: "required"
    }
  }
});

// Authenticate with browser-bound passkey
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: challengeBuffer,
    rpId: "example.com",
    userVerification: "required"
  }
});
```

#### **3. Service Worker & Browser Identity Request Signing**
```javascript
// Intercept and cryptographically sign requests with browser identity
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/')) {
    event.respondWith(signRequestWithDeviceIdentity(event.request));
  }
});

// Sign request with non-exportable browser key
async function signRequestWithDeviceIdentity(request) {
  const browserKey = await getBrowserIdentityKey();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
browserKey,
    requestBody
  );
  // Add cryptographic signature to request
}
```

### **Server-Side Implementation**

#### **1. DPoP Validation**
```python
async def validate_dpop_token(token: str, request: Request):
    # Verify JWS signature
    payload = jose_jws.verify(token, public_key, algorithms=["ES256"])
    
    # Validate DPoP claims
    if payload["htu"] != str(request.url):
        raise HTTPException(400, "Invalid htu")
    if payload["htm"] != request.method:
        raise HTTPException(400, "Invalid htm")
    
    # Check nonce
    if not await validate_nonce(payload["nonce"]):
        raise HTTPException(401, "Invalid nonce")
```

#### **2. WebAuthn Verification**
```python
async def verify_passkey_registration(attestation_object: bytes, client_data: bytes):
    # Parse attestation object
    att = cbor2.loads(attestation_object)
    
    # Verify attestation
    if att["fmt"] == "none":
        # Handle direct attestation
        pass
    elif att["fmt"] == "packed":
        # Handle packed attestation
        pass
    
    # Extract public key
    public_key = extract_public_key(att["authData"])
    return public_key
```

## 🔒 Security Considerations

### **Browser Identity & DPoP Implementation**
- **Non-exportable Keys**: Store private keys in browser's secure key storage, cannot be extracted
- **Browser Binding**: Keys tied to specific browser security context and session
- **Token Expiration**: Implement appropriate token lifetimes with cryptographic binding
- **Nonce Management**: Use cryptographically secure nonces for replay protection
- **Replay Protection**: Validate nonces and timestamps to prevent request replay
- **Key Rotation**: Implement secure key rotation mechanisms
- **Identity Continuity**: Maintain device recognition across sessions for seamless experience

### **WebAuthn & Browser Identity Security**
- **Browser Attestation**: Verify browser attestation for high-security applications
- **User Verification**: Require user verification for sensitive operations
- **Key Protection**: Ensure keys are stored in secure hardware (TPM/SE)
- **Origin Validation**: Validate origin and RP ID for security
- **Device Binding**: Ensure passkeys are bound to specific devices
- **Multi-factor Authentication**: Combine cryptographic keys with biometric verification

### **Device Linking & Attack Prevention**
- **Corporate VDI Support**: Enable secure authentication in virtual desktop environments where WebAuthn/Passkeys are unavailable
- **Step-up Authentication**: Provide additional security verification for sensitive operations using mobile device
- **QR Code Security**: Use short-lived, cryptographically signed tokens for device linking
- **Session Binding**: Bind mobile sessions to desktop sessions with cryptographic proof
- **Real-time Validation**: Validate session state in real-time to prevent session hijacking
- **Secure Communication**: Use HTTPS and secure headers for all cross-device communication
- **Man-in-the-Middle Protection**: Cryptographic signatures prevent device linking attacks
- **Session Hijacking Prevention**: Device-bound sessions cannot be transferred to other devices
- **Account Takeover Protection**: Comprehensive protection against ATO attack vectors

## 📚 API Reference

### **DPoP Endpoints**
- `POST /session/init` - Initialize browser session
- `POST /browser/register` - Register browser identity key
- `POST /dpop/bind` - Bind DPoP token to session
- `POST /api/echo` - Test DPoP-protected API access

### **WebAuthn Endpoints**
- `POST /webauthn/registration/options` - Get registration options
- `POST /webauthn/registration/verify` - Verify registration
- `POST /webauthn/authentication/options` - Get authentication options
- `POST /webauthn/authentication/verify` - Verify authentication

### **Cross-Device & VDI Endpoints**
- `POST /link/start` - Start cross-device linking (VDI/Step-up authentication)
- `GET /link/status/{id}` - Get linking status
- `GET /link/events/{id}` - Real-time linking events
- `POST /link/mobile/start` - Mobile link initiation
- `POST /link/mobile/complete` - Complete mobile linking

## 🤝 Contributing

This is a reference implementation designed to demonstrate best practices for device identity and DPoP security. Contributions are welcome!

### **Development Setup**
1. [Fork the repository](https://github.com/gavinhamilton1/dpop-demo/fork)
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. [Submit a pull request](https://github.com/gavinhamilton1/dpop-demo/pulls)

### **Testing**
```bash
# Run all tests (client + server)
./run_tests.sh

# Run specific test suites
./run_tests.sh client    # Client-side tests only
./run_tests.sh server    # Server-side tests only
./run_tests.sh coverage  # Server tests with coverage

# Manual test commands
npm test                 # Client-side tests (Jest)
pytest test_server.py -v # Server-side tests (pytest)

# Run specific test categories
pytest test_server.py -k "TestSessionManagement" -v
pytest test_server.py -k "TestDPoP" -v
pytest test_server.py -k "TestWebAuthn" -v
```

## 📄 License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **WebAuthn Working Group** for the WebAuthn specification
- **IETF** for the DPoP specification
- **FastAPI** team for the excellent web framework
- **WebCrypto Working Group** for the WebCrypto API

## 📞 Support

For questions, issues, or contributions:
- [Open an issue on GitHub](https://github.com/gavinhamilton1/dpop-demo/issues)
- [View the repository](https://github.com/gavinhamilton1/dpop-demo)
- Check the documentation
- Review the code examples

---

**🔐 Secure • 🚀 Modern • 📱 Cross-Platform • 🛡️ Production-Ready**

This reference implementation demonstrates the future of web authentication with device identity and cryptographic request binding.
