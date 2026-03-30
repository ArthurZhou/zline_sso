import requests
from flask import Flask, request, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = "very_secret_key_123"

# 配置信息（必须与 Rust 端 config.json 一致）
SSO_BASE_URL = "https://jc.d2lib.com/auth/"
CLIENT_ID = "jcradio"
CLIENT_SECRET = "L-HIbj4F4qSkMKqTnr_JfJEp-E2l34N9QPPyMt1fVho"

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f"""
        <h1>登录成功</h1>
        <p>{user}</p>
        <hr>
        <a href='/logout'>登出</a>
        """
    return "<h1>首页</h1><a href='/login'>使用 SSO 登录</a>"

@app.route('/login')
def login():
    # 手动拼接跳转地址
    callback_url = url_for('callback_handler', _external=True)
    auth_url = (
        f"{SSO_BASE_URL}/auth/"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={callback_url}"
        f"&response_type=code"
        f"&state=fixed_state_for_debug"
    )
    return redirect(auth_url)

@app.route('/callback')
def callback_handler(): # 改个名字，避开可能的 request 变量冲突
    # 1. 拿 Code
    code = request.args.get('code')
    if not code:
        return "未能从 URL 获取到 Code", 400

    print(f"\n[DEBUG] 拿到 Code: {code}")

    # 2. 交换 Token (模仿 pwsh 的 POST 请求)
    token_url = f"{SSO_BASE_URL}/auth/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": url_for('callback_handler', _external=True)
    }

    try:
        # 使用 data= 会以 application/x-www-form-urlencoded 发送
        r_token = requests.post(token_url, data=payload, timeout=5)
        
        print(f"[DEBUG] Token 状态码: {r_token.status_code}")
        print(f"[DEBUG] Token 响应体: {r_token.text}")

        if r_token.status_code != 200:
            return f"Token 交换失败: {r_token.text}", 500

        token_data = r_token.json()
        access_token = token_data.get("access_token")

        # 3. 请求 UserInfo (模仿 pwsh 的 GET 请求)
        user_info_url = f"{SSO_BASE_URL}/auth/userinfo"
        r_user = requests.get(
            user_info_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5
        )

        print(f"[DEBUG] UserInfo 响应: {r_user.text}")

        if r_user.status_code != 200:
            return f"获取用户信息失败: {r_user.text}", 500

        # 4. 存入 Session
        session['user'] = r_user.json()
        return redirect(url_for('index'))

    except Exception as e:
        return f"客户端执行出错: {str(e)}", 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # 启动在 8080 端口
    app.run(port=8080, debug=True)