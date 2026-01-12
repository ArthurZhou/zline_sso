from flask import Flask, request, make_response, redirect
import jwt
import requests

app = Flask(__name__)

# --- Configuration ---
SECRET_KEY = "your_secret_key_32_chars_long_!!" # Must match Rust JWT_SECRET
SSO_URL = "http://localhost:8080"
MY_CALLBACK = "http://localhost:5000/auth/callback"

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    if not token:
        # Redirect to SSO login with standard OIDC params
        return redirect(f"{SSO_URL}/index.html?redirect_uri={MY_CALLBACK}&state=random_state_string")

    try:
        # Verify the JWT issued by Rust
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return f"<h1>Hello {data['sub']}</h1><p>Status: Authenticated via OIDC</p><a href='/logout'>Logout</a>"
    except Exception as e:
        return redirect(f"{SSO_URL}/index.html?redirect_uri={MY_CALLBACK}")

@app.route('/auth/callback')
def auth_callback():
    # 1. Get the 'code' (not token) from the URL
    code = request.args.get('code')
    state = request.args.get('state') # In production, verify this matches what you sent
    
    if not code:
        return "Authorization failed: No code provided", 400
    
    # 2. BACK-CHANNEL: Exchange code for token (Server-to-Server)
    # This keeps the token out of the browser history/logs
    try:
        token_resp = requests.post(
            f"{SSO_URL}/auth/token",
            json={"code": code},
            timeout=5
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        id_token = token_data.get('id_token')
    except Exception as e:
        return f"Token exchange failed: {str(e)}", 500

    # 3. Set the cookie and redirect to dashboard
    resp = make_response(redirect('/dashboard'))
    # Use httponly and samesite for security
    resp.set_cookie('auth_token', id_token, httponly=True, samesite='Lax')
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect('/dashboard'))
    resp.delete_cookie('auth_token')
    return resp

if __name__ == '__main__':
    app.run(port=5000, debug=True)