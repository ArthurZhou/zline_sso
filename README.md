# zline sso
为进才中学学生会网络服务开发的校园工作台账号OIDC映射器

## 编译
```
cd ./frontend/
pnpm run build
cd ..
cargo build
cargo build --target x86_64-unknown-linux-musl --release    # or if you want a linux musl prod result
```


python scripts deps:
```
pip install flask pyjwt requests
pip install cryptography
```