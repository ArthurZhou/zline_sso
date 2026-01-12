from flask import Flask, request, make_response, redirect, render_template_string
import jwt

app = Flask(__name__)
SECRET_KEY = "your_secret_key_32_chars_long_!!"
SSO_URL = "http://localhost:8080" # Rust Server
MY_CALLBACK = "http://localhost:5000/auth/callback"

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    if not token:
        # DYNAMIC: Tell Rust where to send the user back to
        return redirect(f"{SSO_URL}/index.html?redirect_uri={MY_CALLBACK}")

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return f"<h1>Hello {data['nickname']}</h1><p>Role: {data['role']}</p><a href='/logout'>Logout</a>"
    except:
        return redirect(f"{SSO_URL}/index.html?redirect_uri={MY_CALLBACK}")

@app.route('/auth/callback')
def auth_callback():
    token = request.args.get('token')
    if not token: return "No token", 400
    
    resp = make_response(redirect('/dashboard'))
    resp.set_cookie('auth_token', token, httponly=True)
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect('/dashboard'))
    resp.delete_cookie('auth_token')
    return resp

if __name__ == '__main__':
    app.run(port=5000)