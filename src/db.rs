use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

use crate::{UserFlag, UserState};
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
    pub restriction_end_time: Option<String>,
    pub last_login_time: Option<String>,
    pub failed_attempts: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginAttempt {
    pub success: bool,
    pub ip_address: Option<String>,
    pub timestamp: String,
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
            restriction_end_time TEXT,
            last_login_time TEXT,
            failed_attempts INTEGER DEFAULT 0
        );",
        [],
    )?;
    // 创建索引以加快查询
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(uid);", []);

    // 登录记录表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            ip_address TEXT,
            success INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
        );",
        [],
    )?;

    // 创建索引以加快查询
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_logs_username ON login_logs(uid);",
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
pub fn record_login_success(conn: &DbConn, uid: &str, ip: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET last_login_time=CURRENT_TIMESTAMP, failed_attempts=0 WHERE uid=?1",
        [uid],
    )?;
    // 记录到审计日志
    log_login_attempt(&conn, &uid, &ip, 1).ok();
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
pub fn record_login_failure(conn: &DbConn, uid: &str, ip: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET failed_attempts=failed_attempts+1 WHERE uid=?1",
        [uid],
    )?;
    // 记录到审计日志
    log_login_attempt(&conn, &uid, &ip, 0).ok();
    Ok(())
}

/// 设置用户限制状态及结束时间
///
/// 更新用户的状态、状态描述和限制结束时间。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
/// - `state`: 新状态码
/// - `description`: 状态描述
/// - `end_time`: 限制结束时间（ISO8601格式，如 "2024-12-31T23:59:59"）
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn set_user_state(
    conn: &DbConn,
    uid: &str,
    state: UserState,
    description: &str,
    end_time: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET state=?1, state_description=?2, restriction_end_time=?3 WHERE uid=?4",
        rusqlite::params![state as i32, description, end_time.to_string(), uid],
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
    success: i32,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO login_logs (uid, ip_address, success) VALUES (?1, ?2, ?3)",
        rusqlite::params![uid, ip_address, success],
    )?;
    Ok(())
}

pub fn get_recent_login_attempts(
    conn: &DbConn,
    uid: &str,
    limit: i32,
) -> Result<Vec<LoginAttempt>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT success, ip_address, timestamp FROM login_logs WHERE uid = ?1 ORDER BY timestamp DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![uid, limit], |row| {
        Ok(LoginAttempt {
            success: row.get::<_, i32>(0)? == 1,
            ip_address: row.get(1)?,
            timestamp: row.get(2)?,
        })
    })?;

    let mut attempts = Vec::new();
    for attempt in rows {
        attempts.push(attempt?);
    }
    Ok(attempts)
}
