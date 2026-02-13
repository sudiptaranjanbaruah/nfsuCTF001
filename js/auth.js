
const SECRET_KEY = "s3cr3t_k3y_f0r_ctf_ch@ll3ng3"; // Vulnerability: Client-side secret!

// --- Utility Functions ---

function base64UrlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return atob(str);
}

async function sign(header, payload, secret) {
    const encoder = new TextEncoder();
    const data = encoder.encode(`${header}.${payload}`);
    const key = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await window.crypto.subtle.sign(
        "HMAC",
        key,
        data
    );
    return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
}

async function verify(token, secret) {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) return false;

    const signature = await sign(headerB64, payloadB64, secret);
    return signature === signatureB64;
}

// --- Auth Logic ---

async function initSession() {
    let token = sessionStorage.getItem('session_token');
    
    if (!token) {
        console.log("No session found. Creating guest session...");
        const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
        const payload = base64UrlEncode(JSON.stringify({ 
            sub: "guest", 
            name: "Guest User", 
            admin: false, 
            iat: Math.floor(Date.now() / 1000) 
        }));
        
        const signature = await sign(header, payload, SECRET_KEY);
        token = `${header}.${payload}.${signature}`;
        
        sessionStorage.setItem('session_token', token);
        console.log("Guest session created:", token);
    } else {
        // Verify existing token on load
        const isValid = await verify(token, SECRET_KEY);
        if (isValid) {
            console.log("Session verified.");
            const payload = JSON.parse(base64UrlDecode(token.split('.')[1]));
            if (payload.admin) {
                console.log("Welcome, Admin!");
                // If on admin page, show flag logic handled there
            }
        } else {
            console.warn("Invalid session token! Resetting...");
            sessionStorage.removeItem('session_token');
            initSession(); // Re-init
        }
    }
}

// Check if we are on the admin page and verify access
if (window.location.pathname.endsWith('admin.html')) {
    document.addEventListener('DOMContentLoaded', async () => {
        const token = sessionStorage.getItem('session_token');
        const messageDiv = document.getElementById('message');
        const contentDiv = document.getElementById('content');

        if (!token) {
            messageDiv.textContent = "Access Denied: No session.";
            return;
        }

        const isValid = await verify(token, SECRET_KEY);
        if (!isValid) {
            messageDiv.textContent = "Access Denied: Invalid Token Signature.";
            return;
        }

        const payload = JSON.parse(base64UrlDecode(token.split('.')[1]));
        if (payload.admin === true) {
            messageDiv.innerHTML = `<span style="color: #4ade80">Access Granted!</span>`;
            contentDiv.style.display = 'block';
        } else {
            messageDiv.innerHTML = "Access Denied: You are not an admin.";
        }
    });
} else {
    // If NOT on admin page, just ensure session exists
    initSession();
}
