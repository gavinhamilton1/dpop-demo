# DPoP Lab Application

This is the lab application for the DPoP Hands-On Lab. Participants will implement the core security controls step by step.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Code editor (VS Code recommended)

### Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the server:**
   ```bash
   python3 server.py
   ```

3. **Open the lab:**
   - Navigate to http://localhost:8000
   - You should see the DPoP Lab interface

## 📁 Project Structure

```
app/
├── index.html          # Main lab interface
├── app.js              # Main application logic (TO BE IMPLEMENTED)
├── utils.js            # Utility functions (provided)
├── server.py           # Backend API server (provided)
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## 🎯 Lab Steps

### Step 1: Browser Identity Key (BIK) Registration
- Generate non-exportable cryptographic key pair
- Store private key securely in IndexedDB
- Register public key with server
- Establish unique browser identity

### Step 2: DPoP Binding
- Generate DPoP key pair
- Create DPoP JWT with required claims
- Bind browser identity to session tokens
- Prevent token theft and replay attacks

### Step 3: WebAuthn Passkey Support
- Check WebAuthn support
- Register passkey with device biometrics
- Authenticate using passkey
- Eliminate password vulnerabilities

### Step 4: Cross-Device Linking
- Generate QR code for device pairing
- Establish WebSocket connection
- Exchange device information securely
- Enable VDI and step-up authentication

## 🔧 Implementation Guide

Each step in `app.js` contains TODO comments with specific implementation instructions. The utilities in `utils.js` provide helper functions for:

- **StorageManager**: IndexedDB operations
- **CryptoUtils**: Cryptographic operations
- **JWTUtils**: JWT creation and verification
- **DPoPUtils**: DPoP-specific operations
- **WebAuthnUtils**: WebAuthn operations
- **QRCodeUtils**: QR code generation
- **APIUtils**: HTTP request helpers

## 🧪 Testing

After implementing each step, test the functionality:

1. **Session Initialization**: Should create session and enable BIK registration
2. **BIK Registration**: Should generate keys and register with server
3. **DPoP Binding**: Should create DPoP proof and bind to session
4. **Passkey Registration**: Should register device biometrics
5. **Cross-Device Linking**: Should generate QR code and establish connection
6. **API Testing**: Should make authenticated requests with DPoP

## 🔍 Debugging

- Check browser console for JavaScript errors
- Check server logs for API errors
- Use browser developer tools to inspect IndexedDB
- Verify network requests in Network tab

## 📚 Resources

- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [IndexedDB API](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)

## 🆘 Getting Help

If you encounter issues:

1. Check the browser console for error messages
2. Verify all dependencies are installed
3. Ensure you're using a modern browser
4. Check that the server is running on port 8000
5. Review the implementation instructions in the TODO comments

## 🎉 Success Criteria

You've successfully completed the lab when:

- ✅ All buttons show green checkmarks
- ✅ Log shows successful completion of each step
- ✅ API test returns successful response
- ✅ Cross-device linking establishes connection
- ✅ You understand the security benefits of each component

Good luck with the implementation! 🚀
