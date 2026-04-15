use base64::{engine::general_purpose, Engine as _};
use rsa::{RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs8::DecodePublicKey;
use std::collections::HashMap;
use rand::thread_rng;

const JINCAI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";

/// 使用进才公钥为数据进行RSA加密
///
/// 本函数使用进才系统的公钥对字典中的每个值进行RSA加密，
/// 用于向进才系统发送敏感数据（如用户名、密码等）。
///
/// # 参数
/// - `data`: 包含待加密数据的HashMap，key为字段名，value为待加密值
///
/// # 返回值
/// 返回加密后的HashMap，其中values为Base64编码的加密数据。
/// 如果某个值加密失败，该项会被跳过，不包含在返回结果中。
/// 如果密钥解析失败，返回空HashMap。
///
/// # 例子
/// ```ignore
/// let mut data = HashMap::new();
/// data.insert("username".to_string(), "user123".to_string());
/// let encrypted = encrypt_for_jincai(data);
/// ```
pub fn encrypt_for_jincai(data: HashMap<String, String>) -> HashMap<String, String> {
    let pub_key_der = general_purpose::STANDARD.decode(JINCAI_PUB_KEY).unwrap_or_default();
    let pub_key = match RsaPublicKey::from_public_key_der(&pub_key_der) {
        Ok(k) => k,
        Err(_) => return HashMap::new(),
    };
    
    let mut out = HashMap::new();
    let mut rng = thread_rng();
    
    for (k, v) in data {
        if let Ok(enc) = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, v.as_bytes()) {
            out.insert(k, general_purpose::STANDARD.encode(enc));
        }
    }
    
    out
}

/// 从进才登录页获取XToken
///
/// 向进才登录页面发起请求，解析HTML响应中的XToken字段。
/// XToken是后续登录请求的必要参数，用于防止CSRF攻击。
///
/// # 返回值
/// - `Ok(String)`: 成功获取XToken值
/// - `Err(String)`: 请求失败或解析XToken失败，包含错误描述
///
/// # 可能的错误
/// - 网络连接失败
/// - HTTP响应读取失败
/// - HTML解析失败（XToken元素不存在或格式异常）
pub async fn get_xtoken() -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.jincai.sh.cn/zlineauthrize/xlogin")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let text = resp
        .text()
        .await
        .map_err(|_| "Failed to read response".to_string())?;

    let id_pos = text.find("id=\"XToken\"").ok_or("XToken element not found")?;
    let start = text[..id_pos].rfind('<').ok_or("Tag parse error")?;
    let end = text[id_pos..].find('>').ok_or("Tag closure missing")? + id_pos;
    let tag = &text[start..=end];

    tag.split("value=\"")
        .nth(1)
        .and_then(|v| v.split('\"').next())
        .map(|v| v.to_string())
        .ok_or("XToken value is empty".into())
}

/// 从进才系统获取用户的外部身份信息
///
/// 使用PZLSystemLogin cookie向进才系统的用户信息获取端点发起请求，
/// 解析HTML响应中的用户ID（xuid）和用户全名（xuxm）字段。
/// 此函数应在成功登录后调用，使用登录返回的cookie。
///
/// # 参数
/// - `pzl_cookie`: 进才登录后返回的PZLSystemLogin cookie值
///
/// # 返回值
/// - `Ok((xuid, xuxm))`: 成功获取用户信息
///   - `xuid`: 用户在进才系统中的ID
///   - `xuxm`: 用户全名
/// - `Err(String)`: 请求失败或解析失败，包含错误描述
///
/// # 可能的错误
/// - Cookie无效或过期
/// - 网络连接失败
/// - xuid或xuxm字段解析失败(返回unknown,unknown)
pub async fn get_external_user_info(pzl_cookie: &str) -> Result<(String, String), String> {
    let client = reqwest::Client::new();
    let url = "https://www.jincai.sh.cn/zlinesystem/xsso/gotox/JCAPW1002";
    
    let resp = client
        .get(url)
        .header("User-Agent", "Mozilla/5.0")
        .header("Cookie", format!("PZLSystemLogin={}", pzl_cookie))
        .send()
        .await
        .map_err(|e| format!("User info request failed: {}", e))?;

    let text = resp.text().await.map_err(|_| "Text encoding error".to_string())?;
    
    let extract = |field: &str| -> Option<String> {
        let pattern = format!("name=\"{}\"", field);
        let pos = text.find(&pattern)?;
        let val_mark = "value=\"";
        let v_start = text[pos..].find(val_mark)? + pos + val_mark.len();
        let v_end = text[v_start..].find('\"')? + v_start;
        Some(text[v_start..v_end].to_string())
    };

    let xuid = extract("xuid").unwrap_or("unknown".to_string());
    let xuxm = extract("xuxm").unwrap_or("unknown".to_string());
    
    Ok((xuid, xuxm))
}

/// 完整的进才登录流程
///
/// 将所有进才相关的操作整合在一个函数中：
/// 1. 获取XToken
/// 2. 构建加密的登录请求
/// 3. 向进才系统发送登录请求
/// 4. 获取用户信息
///
/// # 参数
/// - `http_client`: HTTP客户端
/// - `username`: 用户名
/// - `password`: 密码
///
/// # 返回值
/// - `Ok((xuid, xuxm))`: 登录成功，返回用户在进才系统中的ID和全名
/// - `Err(String)`: 登录失败或任何步骤出错，返回错误描述
pub async fn login_with_jincai(
    http_client: &reqwest::Client,
    username: String,
    password: String,
) -> Result<(String, String), String> {
    // 步骤1: 获取XToken
    let xtoken = get_xtoken().await?;

    // 步骤2: 构建加密的登录请求体
    let mut data = HashMap::new();
    data.insert("XToken".into(), xtoken);
    data.insert("pzlusername".into(), username.clone());
    data.insert("pzlpassword".into(), password);

    let encrypted_body = encrypt_for_jincai(data);

    // 步骤3: 向进才系统发送登录请求
    let resp = http_client
        .post("https://www.jincai.sh.cn/zlineauthrize/xlogin/sysxlogin")
        .form(&encrypted_body)
        .send()
        .await
        .map_err(|e| format!("Login request failed: {}", e))?;

    // 步骤4: 提取响应中的PZLSystemLogin cookie
    let mut pzl_cookie = String::new();
    for cookie in resp.cookies() {
        if cookie.name() == "PZLSystemLogin" {
            pzl_cookie = cookie.value().to_string();
        }
    }

    // 步骤5: 验证登录响应并提取错误信息
    let body = resp
        .json::<serde_json::Value>()
        .await
        .unwrap_or_default();

    if body["succeed"] != "1" {
        let error_msg = body
            .get("errorMsg")
            .and_then(|v| v.as_str())
            .unwrap_or("Login failed");
        return Err(error_msg.to_string());
    }

    // 步骤6: 获取用户信息
    get_external_user_info(&pzl_cookie).await
}
