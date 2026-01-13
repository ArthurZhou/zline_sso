import requests
import concurrent.futures
import time

# 根据你提供的信息，端口为 8097
URL = "http://localhost:8097/auth/login"
PAYLOAD = {
    "encrypted_payload": "test",
    "client_id": "test_client",
    "redirect_uri": "http://127.0.0.1:8080/callback"
}

def send_request(request_id):
    try:
        # 记录发起时间
        start_time = time.time()
        resp = requests.post(URL, json=PAYLOAD, timeout=10)
        end_time = time.time()
        
        print(f"请求 {request_id:02d} | 耗时: {end_time - start_time:.2f}s | "
              f"状态码: {resp.status_code} | 内容: {resp.text[:50]}")
        return resp.status_code
    except Exception as e:
        print(f"请求 {request_id:02d} 失败: {e}")
        return None

def main():
    print(f"开始并发测试，目标地址: {URL}")
    print("正在同时启动 15 个并发请求...")
    
    # 使用线程池模拟并发
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # 瞬间提交所有任务
        futures = [executor.submit(send_request, i) for i in range(1, 16)]
        
        # 统计结果
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # 结果分析
    success_200 = results.count(200)
    unauth_401 = results.count(401)
    limited_429 = results.count(429)
    
    print("\n--- 测试结果分析 ---")
    print(f"成功处理 (200/401): {success_200 + unauth_401} 次")
    print(f"被触发限流 (429): {limited_429} 次")
    
    if limited_429 > 0:
        print("结论: Rate Limit 运行正常！")
    else:
        print("结论: 未触发限流，请检查后端配置或增加并发数。")

if __name__ == "__main__":
    main()