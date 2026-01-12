import json
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_oidc_client(name="alist_service"):
    # 1. 生成 2048 位 RSA 密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. 导出私钥 (PKCS#8 格式) - 用于 Rust 后端签名
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # 3. 导出公钥 (SubjectPublicKeyInfo 格式) - 用于 AList 后台配置
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 4. 生成随机 Client Secret
    client_secret = secrets.token_urlsafe(32)

    # 5. 构造 config.json 的配置块
    config_block = {
        "client_id": name,
        "client_secret": client_secret,
        "private_key_pem": private_pem  # 注意：json.dumps 会自动处理换行符
    }

    print("\n" + "="*50)
    print("1. 请将以下内容复制到 config.json 的 'clients' 部分:")
    print("="*50)
    print(json.dumps({name: config_block}, indent=2))

    print("\n" + "="*50)
    print("2. 请将以下公钥复制到 AList 后台的 'Sso jwt public key' 字段:")
    print("="*50)
    print(public_pem)
    print("="*50)

if __name__ == "__main__":
    client_name = input("请输入应用名称 (例如 alist): ") or "alist"
    generate_oidc_client(client_name)