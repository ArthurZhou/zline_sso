use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

use crate::models::{UserFlag, UserState};
pub type DbPool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type DbConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

/// 用户信息结构体
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub uid: String,
    pub username: String,
    pub role: String,
    pub external_uid: String,
    pub full_name: String,
    pub student_id: Option<String>,
    pub gender: Option<String>,
    pub flag: i32,
    pub state: i32,
    pub state_description: Option<String>,
    /// 限制结束时间（Unix 时间戳，秒；0/NULL 表示无固定结束时间）
    pub restriction_end_time: Option<i64>,
    /// 最后登录时间（Unix 时间戳，秒）
    pub last_login_time: Option<i64>,
    pub failed_attempts: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginAttempt {
    pub success: bool,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    /// 登录时间（Unix 时间戳，秒）
    pub timestamp: i64,
}

/// 初始化数据库
///
/// 创建 users 表（如果不存在）。该表存储用户的基本信息和状态。
/// 开启 WAL 模式以优化高并发下的读写性能。
///
/// # 参数
/// - `path`: 数据库文件路径
///
/// # 返回值
/// - `Ok(())`: 数据库初始化成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn init_db(path: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(path)?;

    #[cfg(not(debug_assertions))]
    {
        // 性能优化：开启 WAL 模式
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        // 性能优化：设置同步模式为 NORMAL
        conn.pragma_update(None, "synchronous", &"NORMAL")?;
    }

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            uid TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            external_uid TEXT,
            full_name TEXT,
            student_id TEXT,
            gender TEXT,
            role TEXT DEFAULT 'user',
            flag INTEGER DEFAULT 0,
            state INTEGER DEFAULT 0,
            state_description TEXT,
            restriction_end_time INTEGER,
            last_login_time INTEGER,
            failed_attempts INTEGER DEFAULT 0
        );",
        [],
    )?;

    // ============ 时间戳迁移（users 表） ============
    // 自本版本起，所有时间均以 Unix 时间戳（秒，INTEGER）存储，前端根据浏览器时区本地化。
    // 旧版本将 restriction_end_time / last_login_time 声明为 TEXT 列：TEXT 亲和性会把
    // 整数强转为文本存储，导致无法按 i64 读取。这里检测旧列类型并重建表：
    // 1. 先把旧文本时间（"YYYY-MM-DD HH:MM:SS" 或 RFC3339）转换为 Unix 时间戳；
    // 2. 重建为 INTEGER 列并拷贝数据。
    let users_needs_rebuild = {
        let mut stmt = conn.prepare("PRAGMA table_info(users);")?;
        let mut rows = stmt.query([])?;
        let mut text_time_column = false;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            let col_type: String = row.get(2)?;
            if (name == "last_login_time" || name == "restriction_end_time")
                && col_type.eq_ignore_ascii_case("TEXT")
            {
                text_time_column = true;
            }
        }
        text_time_column
    };

    if users_needs_rebuild {
        // 迁移期间临时关闭外键：外键开启时 `DROP TABLE users` 会隐式删除其行，
        // 进而通过 login_logs 的 ON DELETE CASCADE 级联清空登录日志。
        let fk_was_on: bool = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i32>(0).map(|v| v != 0))
            .unwrap_or(false);
        if fk_was_on {
            let _ = conn.pragma_update(None, "foreign_keys", "OFF");
        }

        // 1. 旧文本时间 -> Unix 时间戳（秒）。
        //    GLOB 条件保证仅匹配旧文本格式，重复执行不会破坏已是纯数字的值。
        let _ = conn.execute(
            "UPDATE users SET last_login_time = CAST(strftime('%s', last_login_time) AS INTEGER) \
             WHERE last_login_time IS NOT NULL \
             AND last_login_time GLOB '[0-9][0-9][0-9][0-9]-*';",
            [],
        );
        let _ = conn.execute(
            "UPDATE users SET restriction_end_time = CAST(strftime('%s', restriction_end_time) AS INTEGER) \
             WHERE restriction_end_time IS NOT NULL \
             AND restriction_end_time GLOB '[0-9][0-9][0-9][0-9]-*';",
            [],
        );

        // 2. 重建表，将时间列改为 INTEGER
        conn.execute(
            "CREATE TABLE users_new (
                uid TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                external_uid TEXT,
                full_name TEXT,
                student_id TEXT,
                gender TEXT,
                role TEXT DEFAULT 'user',
                flag INTEGER DEFAULT 0,
                state INTEGER DEFAULT 0,
                state_description TEXT,
                restriction_end_time INTEGER,
                last_login_time INTEGER,
                failed_attempts INTEGER DEFAULT 0
            );",
            [],
        )?;
        conn.execute(
            "INSERT INTO users_new \
                (uid, username, external_uid, full_name, student_id, gender, role, flag, state, \
                 state_description, restriction_end_time, last_login_time, failed_attempts) \
             SELECT uid, username, external_uid, full_name, student_id, gender, role, flag, state, \
                 state_description, \
                 CASE WHEN restriction_end_time IS NULL OR restriction_end_time = '' \
                      THEN NULL ELSE CAST(restriction_end_time AS INTEGER) END, \
                 CASE WHEN last_login_time IS NULL OR last_login_time = '' \
                      THEN NULL ELSE CAST(last_login_time AS INTEGER) END, \
                 failed_attempts \
             FROM users;",
            [],
        )?;
        conn.execute("DROP TABLE users;", [])?;
        conn.execute("ALTER TABLE users_new RENAME TO users;", [])?;

        // 恢复外键设置
        if fk_was_on {
            let _ = conn.pragma_update(None, "foreign_keys", "ON");
        }
    }

    // 创建索引以加快查询
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(uid);", []);

    // 登录记录表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            ip_address TEXT,
            country TEXT,
            region TEXT,
            success INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
        );",
        [],
    )?;

    // 如果旧表缺少 geo 字段，按需补齐
    let mut stmt = conn.prepare("PRAGMA table_info(login_logs);")?;
    let mut rows = stmt.query([])?;
    let mut has_country = false;
    let mut has_region = false;
    while let Some(row) = rows.next()? {
        let column_name: String = row.get(1)?;
        if column_name == "country" {
            has_country = true;
        }
        if column_name == "region" {
            has_region = true;
        }
    }
    if !has_country {
        let _ = conn.execute("ALTER TABLE login_logs ADD COLUMN country TEXT;", []);
    }
    if !has_region {
        let _ = conn.execute("ALTER TABLE login_logs ADD COLUMN region TEXT;", []);
    }

    // 创建索引以加快查询
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_logs_username ON login_logs(uid);",
        [],
    );

    // ============ 时间戳迁移（login_logs 表） ============
    // login_logs.timestamp 为 DATETIME（NUMERIC 亲和性），整数可原样存储；
    // 仅需把旧版本的 UTC 文本一次性转换为 Unix 时间戳（秒）。
    // GLOB 条件保证仅匹配旧文本格式，重复执行不会破坏已是整数的时间戳。
    let _ = conn.execute(
        "UPDATE login_logs SET timestamp = CAST(strftime('%s', timestamp) AS INTEGER) \
         WHERE typeof(timestamp) = 'text' AND timestamp GLOB '[0-9][0-9][0-9][0-9]-*';",
        [],
    );

    Ok(())
}

/// 获取用户的完整信息（一次查询获取所有字段）
///
/// 从数据库查询用户的所有信息，包括ID、用户名、角色、外部UID、全名、学号、性别、状态、
/// 状态描述、限制结束时间、最后登录时间和登录失败次数。
/// 这是一个统一的查询入口，避免多次数据库查询。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(Some(user_info))`: 用户存在，返回用户完整信息
/// - `Ok(None)`: 用户不存在
/// - `Err(rusqlite::Error)`: 数据库查询失败
pub fn get_user_full_info(
    conn: &DbConn,
    username: &str,
) -> Result<Option<UserInfo>, rusqlite::Error> {
    conn.query_row(
        "SELECT uid, username, role, external_uid, full_name, student_id, gender, flag, state, state_description, restriction_end_time, last_login_time, failed_attempts FROM users WHERE username = ?1",
        [username],
        |row| Ok(UserInfo {
            uid: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            external_uid: row.get(3)?,
            full_name: row.get(4)?,
            student_id: row.get(5)?,
            gender: row.get(6)?,
            flag: row.get(7)?,
            state: row.get(8)?,
            state_description: row.get(9)?,
            restriction_end_time: row.get(10)?,
            last_login_time: row.get(11)?,
            failed_attempts: row.get(12)?,
        }),
    )
    .optional()
}

/// 插入新用户或更新现有用户信息
///
/// 使用INSERT OR REPLACE语义，如果用户（基于username唯一键）不存在则插入新记录，
/// 否则更新其外部UID、全名、学号、性别和更新时间。用户的初始状态为Normal (0)，角色为'user'。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名（唯一标识）
/// - `external_uid`: 进才系统中的用户ID
/// - `full_name`: 用户全名
/// - `student_id`: 学号 (格式如 240339)
/// - `gender`: 性别
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn upsert_user(
    conn: &DbConn,
    username: &str,
    external_uid: &str,
    full_name: &str,
    student_id: &str,
    gender: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO users (uid, username, external_uid, full_name, student_id, gender, role, state, failed_attempts) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'user', 0, 0)
         ON CONFLICT(username) DO UPDATE SET 
            external_uid=?3, 
            full_name=?4, 
            student_id=?5, 
            gender=?6",
        rusqlite::params![Uuid::new_v4().to_string(), username, external_uid, full_name, student_id, gender],
    )?;
    Ok(())
}

/// 记录登录成功
///
/// 更新用户的最后登录时间，并清空失败次数。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `uid`: 用户uuid
/// - `ip`: 客户端 IP 地址
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn record_login_success(
    conn: &DbConn,
    uid: &str,
    ip: &str,
    country: &str,
    region: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        // 时间统一以 Unix 时间戳（秒）存储
        "UPDATE users SET last_login_time=CAST(strftime('%s','now') AS INTEGER), failed_attempts=0 WHERE uid=?1",
        [uid],
    )?;
    // 记录到审计日志
    log_login_attempt(&conn, &uid, ip, country, region, 1).ok();
    Ok(())
}

/// 记录登录失败
///
/// 增加用户的连续登录失败次数。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `uid`: 用户uuid
/// - `ip`: 客户端 IP 地址
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn record_login_failure(
    conn: &DbConn,
    uid: &str,
    ip: &str,
    country: &str,
    region: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET failed_attempts=failed_attempts+1 WHERE uid=?1",
        [uid],
    )?;
    // 记录到审计日志
    log_login_attempt(&conn, &uid, ip, country, region, 0).ok();
    Ok(())
}

/// 设置用户限制状态及结束时间
///
/// 更新用户的状态、状态描述和限制结束时间。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `uid`: 用户uuid
/// - `state`: 新状态码
/// - `description`: 状态描述
/// - `end_time`: 限制结束时间（Unix 时间戳，秒；0 表示无固定结束时间）
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn set_user_state(
    conn: &DbConn,
    uid: &str,
    state: UserState,
    description: &str,
    end_time: i64,
) -> Result<(), rusqlite::Error> {
    let end_time_param: Option<i64> = if end_time > 0 { Some(end_time) } else { None };
    conn.execute(
        "UPDATE users SET state=?1, state_description=?2, restriction_end_time=?3 WHERE uid=?4",
        rusqlite::params![state as i32, description, end_time_param, uid],
    )?;
    Ok(())
}

/// 设置用户账户标记
///
/// 更新用户的状态、状态描述和限制结束时间。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
/// - `flag`: 新状态码
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn set_user_flag(conn: &DbConn, uid: &str, flag: UserFlag) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET flag=?1 WHERE uid=?2",
        rusqlite::params![flag as i32, uid],
    )?;
    Ok(())
}

/// 记录登录尝试（成功或失败）
///
/// 向 login_logs 表插入一条记录，记录用户的登录尝试及结果。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `uid`: 用户uuid
/// - `ip_address`: 客户端 IP 地址
/// - `success`: 登录是否成功（1 为成功，0 为失败）
///
/// # 返回值
/// - `Ok(())`: 日志记录成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
fn log_login_attempt(
    conn: &DbConn,
    uid: &str,
    ip_address: &str,
    country: &str,
    region: &str,
    success: i32,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        // 时间统一以 Unix 时间戳（秒）存储
        "INSERT INTO login_logs (uid, ip_address, country, region, success, timestamp) \
         VALUES (?1, ?2, ?3, ?4, ?5, CAST(strftime('%s','now') AS INTEGER))",
        rusqlite::params![uid, ip_address, country, region, success],
    )?;
    Ok(())
}

fn mask_ip(ip: String) -> String {
    if ip.contains(':') {
        // 处理 IPv6: 取第一组，后面补星号
        // 例如 2001:0db8:85a3... -> 2001:**
        ip.split(':').next().unwrap_or("").to_string() + ":**"
    } else if ip.contains('.') {
        // 处理 IPv4: 取第一段，后面补星号
        // 例如 192.168.1.1 -> 192.**
        ip.split('.').next().unwrap_or("").to_string() + ".**"
    } else {
        "***".to_string() // 异常格式
    }
}

pub fn get_recent_login_attempts(
    conn: &DbConn,
    uid: &str,
    limit: i32,
) -> Result<Vec<LoginAttempt>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT success, ip_address, country, region, timestamp FROM login_logs WHERE uid = ?1 ORDER BY timestamp DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![uid, limit], |row| {
        let raw_ip = row.get(1).unwrap_or_default(); // 先拿到原始 IP
        Ok(LoginAttempt {
            success: row.get::<_, i32>(0)? == 1,
            ip_address: Some(mask_ip(raw_ip)), // 调用脱敏函数
            country: row.get(2)?,
            region: row.get(3)?,
            timestamp: row.get(4)?,
        })
    })?;

    let mut attempts = Vec::new();
    for attempt in rows {
        attempts.push(attempt?);
    }
    Ok(attempts)
}

/// 全量登录日志条目（管理员使用，含用户名与完整 IP）
#[derive(Debug, Clone, Serialize)]
pub struct AllLoginLog {
    pub username: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    /// 登录时间（Unix 时间戳，秒）
    pub timestamp: i64,
}

/// 查询用户列表（管理员使用）。
///
/// `keyword` 为空时返回全部用户；否则按用户名/姓名/外部ID 模糊匹配。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `keyword`: 搜索关键字（可为空字符串表示全部）
/// - `limit`: 每页条数
/// - `offset`: 偏移量（用于分页）
///
/// # 返回值
/// - `Ok(Vec<UserInfo>)`: 用户列表
pub fn list_users(
    conn: &DbConn,
    keyword: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<UserInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT uid, username, role, external_uid, full_name, student_id, gender, flag, state, \
         state_description, restriction_end_time, last_login_time, failed_attempts \
         FROM users \
         WHERE (?1 = '' OR username LIKE '%'||?1||'%' OR full_name LIKE '%'||?1||'%' OR external_uid LIKE '%'||?1||'%') \
         ORDER BY last_login_time DESC \
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![keyword, limit, offset], |row| {
        Ok(UserInfo {
            uid: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            external_uid: row.get(3)?,
            full_name: row.get(4)?,
            student_id: row.get(5)?,
            gender: row.get(6)?,
            flag: row.get(7)?,
            state: row.get(8)?,
            state_description: row.get(9)?,
            restriction_end_time: row.get(10)?,
            last_login_time: row.get(11)?,
            failed_attempts: row.get(12)?,
        })
    })?;

    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

/// 查询当前 staff 可查看/可操作的带标签用户列表（staff 标签管理使用）。
///
/// 仅返回至少带有一个非基线角色/标签（即 `role` 非空且不等于基线 `user`）的用户，
/// 且满足以下限制：
/// - 用户必须带有 `manageable_tags` 中的至少一个标签（与当前 staff 共享标签）；
/// - 排除本身带 `staff` 标签的用户（staff 不能对其他 staff 进行添加/移除操作，
///   也不应看到其他 staff 的身份）。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `keyword`: 搜索关键字（用户名/姓名/外部ID 模糊匹配）
/// - `manageable_tags`: 当前 staff 可管理的标签列表（其自身除 `user`/`staff`/`admin` 外的标签）
/// - `limit`: 每页条数
/// - `offset`: 偏移量（用于分页）
///
/// # 返回值
/// - `Ok(Vec<UserInfo>)`: 用户列表
pub fn list_tagged_users(
    conn: &DbConn,
    keyword: &str,
    manageable_tags: &[String],
    limit: i64,
    offset: i64,
) -> Result<Vec<UserInfo>, rusqlite::Error> {
    // 无任何可管理标签时，staff 看不到任何用户
    if manageable_tags.is_empty() {
        return Ok(Vec::new());
    }

    let mut sql = String::from(
        "SELECT uid, username, role, external_uid, full_name, student_id, gender, flag, state, \
         state_description, restriction_end_time, last_login_time, failed_attempts \
         FROM users \
         WHERE (role IS NOT NULL AND role != '' AND role != 'user') \
           AND (',' || role || ',') NOT LIKE '%,staff,%' \
           AND (",
    );

    // ?1 keyword, ?2 limit, ?3 offset；标签条件从 ?4 开始
    let mut params: Vec<rusqlite::types::Value> = vec![
        keyword.to_string().into(),
        limit.into(),
        offset.into(),
    ];

    for (i, tag) in manageable_tags.iter().enumerate() {
        if i > 0 {
            sql.push_str(" OR ");
        }
        // 以逗号包裹后精确匹配单个标签，避免 `a` 误匹配 `ab` 等前缀
        sql.push_str("(',' || role || ',') LIKE '%,' || ?");
        sql.push_str(&(4 + i).to_string());
        sql.push_str(" || ',%'");
        params.push(tag.clone().into());
    }

    sql.push_str(
        ") AND (?1 = '' OR username LIKE '%'||?1||'%' OR full_name LIKE '%'||?1||'%' OR external_uid LIKE '%'||?1||'%') \
         ORDER BY last_login_time DESC \
         LIMIT ?2 OFFSET ?3",
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params), |row| {
        Ok(UserInfo {
            uid: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            external_uid: row.get(3)?,
            full_name: row.get(4)?,
            student_id: row.get(5)?,
            gender: row.get(6)?,
            flag: row.get(7)?,
            state: row.get(8)?,
            state_description: row.get(9)?,
            restriction_end_time: row.get(10)?,
            last_login_time: row.get(11)?,
            failed_attempts: row.get(12)?,
        })
    })?;

    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

/// 设置用户角色（管理员使用）。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `uid`: 用户 uuid
/// - `role`: 新角色，如 "user" / "admin" / "staff" 或逗号分隔的多个角色
pub fn set_user_role(conn: &DbConn, uid: &str, role: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET role=?2 WHERE uid=?1",
        rusqlite::params![uid, role],
    )?;
    Ok(())
}

/// 添加用户（管理员使用）。
///
/// 直接插入一条新用户记录，默认状态为 Normal，失败次数为 0。
/// 调用方需保证 `username` 在当前表中不存在（否则会违反唯一约束）。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名（唯一标识）
/// - `role`: 初始角色/标签（可为逗号分隔的多个）
/// - `full_name`: 姓名（可为空）
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn add_user(
    conn: &DbConn,
    username: &str,
    role: &str,
    full_name: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO users (uid, username, external_uid, full_name, role, state, failed_attempts) \
         VALUES (?1, ?2, '', ?3, ?4, 0, 0)",
        rusqlite::params![Uuid::new_v4().to_string(), username, full_name, role],
    )?;
    Ok(())
}

/// 删除用户（管理员使用）。
///
/// 删除指定用户名对应的用户记录，并顺带清理其登录日志（避免外键残留）。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 要删除的用户名
///
/// # 返回值
/// - `Ok(())`: 操作成功（用户不存在时也返回 Ok，相当于无操作）
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn delete_user(conn: &DbConn, username: &str) -> Result<(), rusqlite::Error> {
    if let Some(info) = get_user_full_info(conn, username)? {
        conn.execute("DELETE FROM login_logs WHERE uid = ?1", [&info.uid])?;
        conn.execute("DELETE FROM users WHERE uid = ?1", [&info.uid])?;
    }
    Ok(())
}

/// 查询全量登录日志（管理员使用，跨所有用户）。
///
/// `keyword` 为空时返回全部；否则按用户名模糊匹配。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `keyword`: 搜索关键字（可为空字符串表示全部）
/// - `limit`: 每页条数
/// - `offset`: 偏移量（用于分页）
///
/// # 返回值
/// - `Ok(Vec<AllLoginLog>)`: 日志列表
pub fn list_all_login_logs(
    conn: &DbConn,
    keyword: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AllLoginLog>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT u.username, l.success, l.ip_address, l.country, l.region, l.timestamp \
         FROM login_logs l JOIN users u ON u.uid = l.uid \
         WHERE (?1 = '' OR u.username LIKE '%'||?1||'%') \
         ORDER BY l.timestamp DESC \
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![keyword, limit, offset], |row| {
        Ok(AllLoginLog {
            username: row.get(0)?,
            success: row.get::<_, i32>(1)? == 1,
            ip_address: row.get(2)?,
            country: row.get(3)?,
            region: row.get(4)?,
            timestamp: row.get(5)?,
        })
    })?;

    let mut logs = Vec::new();
    for row in rows {
        logs.push(row?);
    }
    Ok(logs)
}
