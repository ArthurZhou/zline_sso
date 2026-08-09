//! Zline封装
//!
//! zlinedesk是上海市大多高中使用的校园工作台系统，理论上这里的代码适用于所有zline类系统
//! 如果需要针对您的学校适配，只需要修改如下的代码即可
//!

use base64::{Engine as _, engine::general_purpose};
use once_cell::sync::Lazy;
use rand::thread_rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;

const ZLINEI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";
const STUDENTS_DATA_CSV: &str = "students_data.csv";

/// 使用zline公钥为数据进行RSA加密
///
/// 本函数使用zline系统的公钥对字典中的每个值进行RSA加密，
/// 用于向zline系统发送敏感数据（如用户名、密码等）。
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
    let pub_key_der = general_purpose::STANDARD
        .decode(ZLINEI_PUB_KEY)
        .unwrap_or_default();
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

/// 从zline登录页获取XToken
///
/// 向zline登录页面发起请求，解析HTML响应中的XToken字段。
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
pub async fn get_xtoken(client: &reqwest::Client) -> Result<String, String> {
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

    let id_pos = text
        .find("id=\"XToken\"")
        .ok_or("XToken element not found")?;
    let start = text[..id_pos].rfind('<').ok_or("Tag parse error")?;
    let end = text[id_pos..].find('>').ok_or("Tag closure missing")? + id_pos;
    let tag = &text[start..=end];

    tag.split("value=\"")
        .nth(1)
        .and_then(|v| v.split('\"').next())
        .map(|v| v.to_string())
        .ok_or("XToken value is empty".into())
}

/// 从CSV文件查询用户信息
///
/// 从指定的CSV文件中根据电脑号(xuid)查找记录编号(student_id)和性别。
/// CSV结构: 记录编号,电脑号,学号,姓名,性别
///
/// # 参数
/// - `file_path`: CSV文件路径
/// - `target_xuid`: 待查找的电脑号(xuid)
///
/// # 返回值
/// - `Some((student_id, gender))`: 找到匹配项
/// - `None`: 未找到匹配项或文件读取失败
// 全局CSV缓存：键为 xuid -> (student_id, gender)
static CSV_CACHE: Lazy<RwLock<HashMap<String, (String, String)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// 从CSV文件加载到内存缓存。建议在程序启动时调用一次。
pub fn load_csv_cache(file_path: &str) -> Result<(), std::io::Error> {
    let csv_data = fs::read_to_string(file_path)?;
    let mut map = HashMap::new();

    for line in csv_data.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let columns: Vec<&str> = line.split(',').collect();
        if columns.len() >= 5 {
            let xuid = columns[1].trim().to_string();
            let record_id = columns[0].trim().to_string();
            let gender = columns[4].trim().to_string();
            map.insert(xuid, (record_id, gender));
        }
    }

    let mut guard = CSV_CACHE.write().unwrap();
    *guard = map;
    Ok(())
}

/// 从内存缓存中查询用户信息
fn find_user_in_csv_file(_file_path: &str, target_xuid: &str) -> Option<(String, String)> {
    let guard = CSV_CACHE.read().unwrap();
    guard.get(target_xuid).cloned()
}

/// 从zline系统获取用户的外部身份信息
///
/// 使用PZLSystemLogin cookie向zline系统的用户信息获取端点发起请求，
/// 解析HTML响应中的用户ID（xuid）和用户全名（xuxm）字段。
/// 此函数应在成功登录后调用，使用登录返回的cookie。
///
/// # 参数
/// - `pzl_cookie`: zline登录后返回的PZLSystemLogin cookie值
///
/// # 返回值
/// - `Ok((xuid, xuxm))`: 成功获取用户信息
///   - `xuid`: 用户在zline系统中的ID
///   - `xuxm`: 用户全名
/// - `Err(String)`: 请求失败或解析失败，包含错误描述
///
/// # 可能的错误
/// - Cookie无效或过期
/// - 网络连接失败
/// - xuid或xuxm字段解析失败(返回unknown,unknown)
pub async fn get_external_user_info(
    client: &reqwest::Client,
    pzl_cookie: &str,
) -> Result<(String, String, String, String), String> {
    let urls = [
        "https://www.jincai.sh.cn/zlinesystem/xsso/gotox/JCAPW1002",
        "https://www.jincai.sh.cn/zlinesystem/xsso/gotox/JCA2W1004",
    ];

    let mut last_text;

    for url in urls {
        let resp = client
            .get(url)
            .header("User-Agent", "Mozilla/5.0")
            .header("Cookie", format!("PZLSystemLogin={}", pzl_cookie))
            .send()
            .await
            .map_err(|e| format!("User info request failed: {}", e))?;

        last_text = resp
            .text()
            .await
            .map_err(|_| "Text encoding error".to_string())?;

        // 如果页面包含“无权访问”，则尝试下一个 URL
        if last_text.contains("无权访问") {
            continue;
        }

        // 提取逻辑
        let extract = |text: &str, field: &str| -> Option<String> {
            let pattern = format!("name=\"{}\"", field);
            let pos = text.find(&pattern)?;
            let val_mark = "value=\"";
            let v_start = text[pos..].find(val_mark)? + pos + val_mark.len();
            let v_end = text[v_start..].find('\"')? + v_start;
            Some(text[v_start..v_end].to_string())
        };

        let xuid = extract(&last_text, "xuid");
        let xuxm = extract(&last_text, "xuxm");

        // 只有当成功提取到其中一个字段且不是 "unknown" 时才返回
        if xuid.is_some() || xuxm.is_some() {
            let xuid_val = xuid.unwrap_or_else(|| "".to_string());
            let xuxm_val = xuxm.unwrap_or_else(|| "".to_string());

            // 从CSV中查询学号和性别
            let (student_id, gender) = find_user_in_csv_file(STUDENTS_DATA_CSV, &xuid_val)
                .unwrap_or(("".to_string(), "".to_string()));

            return Ok((xuid_val, xuxm_val, student_id, gender));
        }
    }

    Ok((
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
    ))
}

/// 完整的zline登录流程
///
/// 将所有zline相关的操作整合在一个函数中：
/// 1. 获取XToken
/// 2. 构建加密的登录请求
/// 3. 向zline系统发送登录请求
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
) -> Result<String, String> {
    // 步骤1: 获取XToken
    let xtoken = get_xtoken(http_client).await?;

    // 步骤2: 构建加密的登录请求体
    let mut data = HashMap::new();
    data.insert("XToken".into(), xtoken);
    data.insert("pzlusername".into(), username);
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
    let body = resp.json::<serde_json::Value>().await.unwrap_or_default();

    if body["succeed"] != "1" {
        let error_msg = body
            .get("errorMsg")
            .and_then(|v| v.as_str())
            .unwrap_or("Login failed");
        return Err(error_msg.to_string());
    }

    Ok(pzl_cookie)
}
