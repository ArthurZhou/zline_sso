use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

/// 用户信息结构体
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
    pub external_uid: String,
    pub full_name: String,
    pub student_id: Option<String>,
    pub gender: Option<String>,
    pub state: i32,
    pub state_description: Option<String>,
    pub restriction_end_time: Option<String>,
    pub last_login_time: Option<String>,
    pub failed_attempts: i32,
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
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            external_uid TEXT,
            full_name TEXT,
            student_id TEXT,
            gender TEXT,
            role TEXT DEFAULT 'user',
            state INTEGER DEFAULT 0,
            state_description TEXT,
            restriction_end_time TEXT,
            last_login_time TEXT,
            failed_attempts INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );",
        [],
    )?;
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
    conn: &Connection,
    username: &str,
) -> Result<Option<UserInfo>, rusqlite::Error> {
    conn.query_row(
        "SELECT id, username, role, external_uid, full_name, student_id, gender, state, state_description, restriction_end_time, last_login_time, failed_attempts FROM users WHERE username = ?1",
        [username],
        |row| Ok(UserInfo {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            external_uid: row.get(3)?,
            full_name: row.get(4)?,
            student_id: row.get(5)?,
            gender: row.get(6)?,
            state: row.get(7)?,
            state_description: row.get(8)?,
            restriction_end_time: row.get(9)?,
            last_login_time: row.get(10)?,
            failed_attempts: row.get(11)?,
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
    conn: &Connection,
    username: &str,
    external_uid: &str,
    full_name: &str,
    student_id: &str,
    gender: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO users (id, username, external_uid, full_name, student_id, gender, role, state, failed_attempts) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'user', 0, 0)
         ON CONFLICT(username) DO UPDATE SET 
            external_uid=?3, 
            full_name=?4, 
            student_id=?5, 
            gender=?6, 
            updated_at=CURRENT_TIMESTAMP",
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
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn record_login_success(conn: &Connection, username: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET last_login_time=CURRENT_TIMESTAMP, failed_attempts=0, updated_at=CURRENT_TIMESTAMP WHERE username=?1",
        [username],
    )?;
    Ok(())
}

/// 记录登录失败
///
/// 增加用户的连续登录失败次数。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn record_login_failure(conn: &Connection, username: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET failed_attempts=failed_attempts+1, updated_at=CURRENT_TIMESTAMP WHERE username=?1",
        [username],
    )?;
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
pub fn set_user_restriction(
    conn: &Connection,
    username: &str,
    state: i32,
    description: &str,
    end_time: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE users SET state=?1, state_description=?2, restriction_end_time=?3, updated_at=CURRENT_TIMESTAMP WHERE username=?4",
        rusqlite::params![state, description, end_time.to_string(), username],
    )?;
    Ok(())
}
