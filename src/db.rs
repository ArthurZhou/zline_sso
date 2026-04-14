use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

/// 初始化数据库
///
/// 创建 users 表（如果不存在）。该表存储用户的基本信息和状态。
///
/// # 参数
/// - `path`: 数据库文件路径
///
/// # 返回值
/// - `Ok(())`: 数据库初始化成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn init_db(path: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            external_uid TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            state INTEGER DEFAULT 0,
            state_description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );",
        [],
    )?;
    Ok(())
}

/// 根据用户名获取用户状态信息
///
/// 从数据库中查询指定用户名的用户状态和状态描述。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(Some((state, description)))`: 用户存在，返回状态码和描述文本
///   - `state`: 用户状态码（0=Normal, 1=Restricted, 2=Locked, 3=BypassExternal）
///   - `description`: 状态描述（可能为None）
/// - `Ok(None)`: 用户不存在
/// - `Err(rusqlite::Error)`: 数据库查询失败
pub fn get_user_state(conn: &Connection, username: &str) -> Result<Option<(i32, Option<String>)>, rusqlite::Error> {
    conn.query_row(
        "SELECT state, state_description FROM users WHERE username = ?1",
        [username],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// 根据用户名获取用户完整信息
///
/// 从数据库查询用户的ID、角色、外部UID、状态和状态描述。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(Some((id, role, external_uid, state, description)))`: 用户存在
///   - `id`: 用户的唯一标识符（UUID）
///   - `role`: 用户角色（如'user'、'admin'等）
///   - `external_uid`: 进才系统中的用户ID
///   - `state`: 用户状态码
///   - `description`: 状态描述
/// - `Ok(None)`: 用户不存在
/// - `Err(rusqlite::Error)`: 数据库查询失败
pub fn get_user_info(conn: &Connection, username: &str) -> Result<Option<(String, String, String, i32, Option<String>)>, rusqlite::Error> {
    conn.query_row(
        "SELECT id, role, external_uid, state, state_description FROM users WHERE username = ?1",
        [username],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )
    .optional()
}

/// 获取用户的OAuth相关信息
///
/// 从数据库查询用户的角色、外部UID和全名，用于生成OAuth token和userinfo响应。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(Some((role, external_uid, full_name)))`: 用户存在
///   - `role`: 用户角色
///   - `external_uid`: 进才系统中的用户ID
///   - `full_name`: 用户全名
/// - `Ok(None)`: 用户不存在
/// - `Err(rusqlite::Error)`: 数据库查询失败
pub fn get_user_oauth_info(conn: &Connection, username: &str) -> Result<Option<(String, String, String)>, rusqlite::Error> {
    conn.query_row(
        "SELECT role, external_uid, full_name FROM users WHERE username = ?1",
        [username],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
}

/// 获取用户的全名
///
/// 从数据库查询指定用户的全名。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名
///
/// # 返回值
/// - `Ok(Some(full_name))`: 用户存在，返回其全名
/// - `Ok(None)`: 用户不存在
/// - `Err(rusqlite::Error)`: 数据库查询失败
pub fn get_user_full_name(conn: &Connection, username: &str) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        "SELECT full_name FROM users WHERE username = ?1",
        [username],
        |row| row.get(0),
    )
    .optional()
}

/// 插入新用户或更新现有用户信息
///
/// 使用INSERT OR REPLACE语义，如果用户（基于username唯一键）不存在则插入新记录，
/// 否则更新其外部UID、全名和更新时间。用户的初始状态为Normal (0)，角色为'user'。
///
/// # 参数
/// - `conn`: 数据库连接
/// - `username`: 用户名（唯一标识）
/// - `external_uid`: 进才系统中的用户ID
/// - `full_name`: 用户全名
///
/// # 返回值
/// - `Ok(())`: 操作成功
/// - `Err(rusqlite::Error)`: 数据库操作失败
pub fn upsert_user(
    conn: &Connection,
    username: &str,
    external_uid: &str,
    full_name: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO users (id, username, external_uid, full_name, role, state) 
         VALUES (?1, ?2, ?3, ?4, 'user', 0)
         ON CONFLICT(username) DO UPDATE SET external_uid=?3, full_name=?4, updated_at=CURRENT_TIMESTAMP",
        rusqlite::params![Uuid::new_v4().to_string(), username, external_uid, full_name],
    )?;
    Ok(())
}
