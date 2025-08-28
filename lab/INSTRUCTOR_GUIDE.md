# Instructor Guide: DPoP Hands-On Lab

## 🎯 Overview

This 30-minute hands-on lab teaches participants how to implement browser identity and DPoP security controls. The lab is designed to be interactive, with participants building a working implementation step-by-step.

## ⏰ Timing Breakdown

### **Part 1: Setup & Introduction (5 minutes)**
- **0:00-1:00**: Welcome and lab overview
- **1:00-3:00**: Scaffold setup and project structure explanation
- **3:00-5:00**: Running the basic application

### **Part 2: Core Implementation (20 minutes)**
- **5:00-10:00**: Step 1 - BIK Registration (5 min)
- **10:00-15:00**: Step 2 - DPoP Binding (5 min)
- **15:00-20:00**: Step 3 - API Testing (5 min)
- **20:00-25:00**: Step 4 - WebAuthn Integration (5 min)
- **25:00-30:00**: Step 5 - Cross-Device Linking (5 min)

### **Part 3: Testing & Wrap-up (5 minutes)**
- **30:00-33:00**: Testing the complete flow
- **33:00-35:00**: Q&A and real-world applications discussion

## 🎤 Talking Points & Script

### **Opening (0:00-1:00)**

> "Welcome to the DPoP Hands-On Lab! Today we're going to build a secure browser identity system that demonstrates proof-of-possession. This is cutting-edge security technology that's being adopted by major platforms and enterprises.
> 
> **Why is this important?** Traditional authentication relies on passwords and tokens that can be stolen. DPoP provides cryptographic proof that the client actually possesses the key, making attacks much harder.
> 
> **What we'll build:** A complete system with browser identity keys, DPoP binding, passkey authentication, and cross-device linking - all in 30 minutes!"

### **Setup Explanation (1:00-3:00)**

> "Let's look at our lab application. We have a simple web app with a basic UI and a Python FastAPI backend. The key files are:
> 
> - `index.html` - Our main interface
> - `app.js` - Main application logic with TODO comments (we'll implement this)
> - `app-complete.js` - Complete implementation for reference
> - `server.py` - Backend API (already implemented)
> - `utils.js` - Helper functions (we'll use these)
> 
> **The lab application provides:**
> - Basic UI with buttons for each step
> - TODO comments in `app.js` for guided implementation
> - Server endpoints for authentication
> - Utility functions for crypto operations
> - IndexedDB setup for secure storage
> 
> **Implementation approach:**
> - Each method contains TODO comments with hints
> - Students implement one step at a time
> - Detailed logging shows what's happening
> - Reference implementation available if needed"

### **Step 1: BIK Registration (5:00-10:00)**

> "**Step 1: Browser Identity Key Registration**
> 
> First, we need to establish a unique identity for this browser. We'll generate a cryptographic key pair that can never leave the browser - this is our Browser Identity Key (BIK).
> 
> **Key concepts:**
> - Non-exportable keys using Web Crypto API
> - Secure storage in IndexedDB
> - Key thumbprint for identification
> 
> **Implementation:**
> 1. Generate EC key pair with `crypto.subtle.generateKey()`
> 2. Store in IndexedDB using the provided utilities
> 3. Send public key to server for registration
> 4. Server validates and stores key thumbprint"

**Common Questions:**
- *"Why can't we export the private key?"* - Security! If it could be exported, it could be stolen.
- *"What's a key thumbprint?"* - A unique identifier derived from the public key.

### **Step 2: DPoP Binding (10:00-15:00)**

> "**Step 2: DPoP Binding**
> 
> Now we'll create a DPoP proof that cryptographically binds our browser identity to a session token. This prevents token theft and replay attacks.
> 
> **Key concepts:**
> - DPoP tokens are JWTs with specific claims
> - `jti` (JWT ID) must be unique per request
> - `htm` (HTTP method) and `htu` (HTTP URI) prevent replay
> - `iat` (issued at) prevents timing attacks
> 
> **Implementation:**
> 1. Generate a new DPoP key pair
> 2. Create DPoP JWT with required claims
> 3. Send to server for binding
> 4. Server issues binding token"

**Common Questions:**
- *"Why do we need a separate DPoP key?"* - Separation of concerns. BIK is for identity, DPoP is for session binding.
- *"What prevents replay attacks?"* - The `jti` must be unique, and `htm`/`htu` must match the actual request.

### **Step 3: WebAuthn Integration (15:00-20:00)**

> "**Step 3: WebAuthn Passkey Support**
> 
> Now we'll add passwordless authentication using the device's biometric authenticator or security key. This eliminates password vulnerabilities.
> 
> **Key concepts:**
> - WebAuthn uses public key cryptography
> - User verification (biometric, PIN, etc.)
> - Attestation for key authenticity
> - Cross-platform compatibility
> 
> **Implementation:**
> 1. Check WebAuthn support
> 2. Get registration options from server
> 3. Create credentials with `navigator.credentials.create()`
> 4. Send attestation to server for verification"

**Common Questions:**
- *"What if the device doesn't have biometrics?"* - WebAuthn supports security keys, PINs, and other verification methods.
- *"How does this work across devices?"* - Passkeys can be synced via cloud providers or used with security keys.

### **Step 4: Cross-Device Linking (20:00-25:00)**

> "**Step 4: Cross-Device Linking**
> 
> Finally, we'll implement secure communication between devices. This enables VDI environments and step-up authentication scenarios.
> 
> **Key concepts:**
> - QR codes for easy device pairing
> - WebSocket for real-time communication
> - Cryptographic verification of device identity
> - Secure data sharing between devices
> 
> **Implementation:**
> 1. Generate QR code with linking URL
> 2. Establish WebSocket connection
> 3. Exchange device information securely
> 4. Enable real-time data sharing"

**Common Questions:**
- *"How is this secure?"* - Each device has its own identity keys, and communication is cryptographically verified.
- *"What about network security?"* - WebSocket connections use TLS, and we add additional cryptographic verification.

### **Testing & Wrap-up (25:00-30:00)**

> "**Testing Our Implementation**
> 
> Let's test the complete flow:
> 1. Initialize session
> 2. Register BIK
> 3. Bind DPoP
> 4. Register passkey
> 5. Test cross-device linking
> 
> **Real-world applications:**
> - Enterprise SSO with device binding
> - Financial services with step-up authentication
> - Healthcare applications with device verification
> - IoT device management
> 
> **Key security benefits:**
> - No passwords to steal
> - Tokens can't be replayed
> - Device identity is cryptographically proven
> - Cross-device communication is secure"

## 🎯 Facilitation Tips

### **Before the Lab**
- Test the scaffold on different browsers
- Prepare for common technical issues
- Have backup solutions ready
- Set up screen sharing for demonstrations

### **During the Lab**
- **Keep energy high** - This is exciting technology!
- **Encourage questions** - Security concepts can be complex
- **Provide context** - Explain why each step matters
- **Celebrate successes** - Each working step is a win
- **Help strugglers** - Some participants may need extra guidance

### **Common Issues & Solutions**

**Browser Compatibility:**
- Chrome/Edge: Full WebAuthn support
- Firefox: Good support, may need HTTPS
- Safari: Limited WebAuthn support

**Crypto API Issues:**
- Ensure HTTPS or localhost
- Check browser console for errors
- Verify key generation parameters

**WebSocket Issues:**
- Check server is running
- Verify WebSocket URL format
- Look for CORS issues

### **Engagement Strategies**

1. **Ask for predictions** - "What do you think will happen when we click this button?"
2. **Explain the security implications** - "Why is this more secure than passwords?"
3. **Connect to real-world** - "Where have you seen this technology used?"
4. **Encourage experimentation** - "Try changing this parameter and see what happens"

### **Assessment & Success Metrics**

**Participants should be able to:**
- ✅ Explain what DPoP is and why it's important
- ✅ Implement basic cryptographic operations
- ✅ Understand WebAuthn concepts
- ✅ Describe cross-device security challenges
- ✅ Identify real-world applications

**Success indicators:**
- Working implementation by end of lab
- Understanding of security benefits
- Ability to explain concepts to others
- Interest in applying to their own projects

## 🚀 Post-Lab Activities

### **Optional Extensions (if time permits)**
- Add nonce challenge handling
- Implement token refresh flows
- Add additional security controls
- Explore enterprise integration patterns

### **Follow-up Resources**
- DPoP RFC 9449 deep dive
- WebAuthn implementation guides
- Enterprise security patterns
- Real-world case studies

### **Next Steps for Participants**
- Apply concepts to their own applications
- Explore advanced DPoP features
- Consider enterprise integration
- Join security communities and discussions

## 📚 Additional Resources

- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [Web Crypto API Guide](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Security Best Practices](https://owasp.org/www-project-top-ten/)

---

**Remember:** The goal is not just to build working code, but to understand the security principles and real-world applications. Encourage participants to think about how they can apply these concepts to their own projects!
