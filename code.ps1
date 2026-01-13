# ================= 配置区 =================
$SSO_URL = "http://127.0.0.1:8097"
$CLIENT_ID = "test_client"
$CLIENT_SECRET = "test_client_secret"
$REDIRECT_URI = "http://localhost:8080/callback"

# 这里填你浏览器里拿到的最新 Code
$CODE = "4d6d715c-7f2b-4e3c-a4ff-d4d9e0511f89" 
# ==========================================

Write-Host "`n>>> [开始验证 SSO 流程]" -ForegroundColor Cyan -Style Bold

# 1. 验证限流配置 (读取 config.json 的运行状态)
Write-Host "`n[步骤 1] 正在探测限流配置..." -ForegroundColor Gray
try {
    $crypto = Invoke-RestMethod -Uri "$SSO_URL/auth/crypto-config" -Method Get
    Write-Host "  OK: 成功连接后端，发现限流已配置。" -ForegroundColor Green
} catch {
    Write-Host "  WARN: 无法获取配置，可能是接口路径不对。" -ForegroundColor Yellow
}

# 2. 交换 Token
Write-Host "`n[步骤 2] 正在执行 Token 交换 (Grant Type: authorization_code)..." -ForegroundColor Gray
$tokenBody = @{
    grant_type    = "authorization_code"
    code          = $CODE
    client_id     = $CLIENT_ID
    client_secret = $CLIENT_SECRET
    redirect_uri  = $REDIRECT_URI
}

try {
    $tokenResp = Invoke-RestMethod -Uri "$SSO_URL/auth/token" -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    $accessToken = $tokenResp.access_token
    Write-Host "  SUCCESS: 拿到 Access Token！" -ForegroundColor Green
    Write-Host "  Token 预览: $($accessToken.Substring(0, 30))..." -ForegroundColor DarkGray

    # 3. 请求用户信息 (验证数据库入库)
    Write-Host "`n[步骤 3] 正在请求 UserInfo (验证 SQLite 自动入库)..." -ForegroundColor Gray
    $headers = @{ "Authorization" = "Bearer $accessToken" }
    $userInfo = Invoke-RestMethod -Uri "$SSO_URL/auth/userinfo" -Method Get -Headers $headers

    Write-Host "  SUCCESS: 获取用户信息成功！" -ForegroundColor Green
    Write-Host "----------------------------------"
    $userInfo | Format-List | Out-String | Write-Host -ForegroundColor White
    Write-Host "----------------------------------"

} catch {
    Write-Host "  FAIL: 流程中断！" -ForegroundColor Red
    # 兼容性读取错误内容
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Host "  后端报错内容: $errorBody" -ForegroundColor Yellow
    } else {
        Write-Host "  异常原因: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host "`n提示：Code 只能使用一次，如果报错 invalid_grant，请去浏览器拿个新 Code 再跑。" -ForegroundColor Cyan
}

Write-Host "`n>>> [验证结束]`n" -ForegroundColor Cyan