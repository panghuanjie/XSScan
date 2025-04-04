# 📌 XSScan v1.2 更新日志（2025-04-04）

我们很高兴地发布 XSScan v1.2 版本！  
这是一次全面增强的更新，带来更强的稳定性、更深度的检测能力和更完善的报告展示体验。

---

## ✨ 新特性与增强

### 🔍 爬虫增强（更智能、更隐蔽）

- 增加随机 `User-Agent`，模拟真实用户环境  
- 有 70% 概率添加随机 `Referer` 头  
- 请求之间随机延迟，模拟人类点击行为  
- 更稳定的错误处理机制，避免中断检测流程  

### 🍪 支持自定义 Cookie

- 允许用户设置自定义 Cookie 字符串，便于深入认证后的页面及后台接口进行测试  
- 配置项更加灵活，适用于多种测试场景  

### 📄 HTML 报告优化升级

- 优化 HTML 报告视觉样式  
- 自动统计漏洞数量（按请求类型划分）  
- 每条漏洞前显示请求方式（如【GET】、【POST】）  
- 精简响应内容，仅展示 Payload 上下文  
- 请求参数完整呈现，助力溯源定位问题  

### 🎨 视觉细节优化

- 再次美化横幅输出，增强视觉一致性  
- 控制台输出结构清晰、关键点高亮  

---

## 🐛 Bug 修复

- 修复部分页面中爬虫提前终止的问题  
- 优化 HTML 报告在特殊字符下的编码兼容性  
- 修复特定 Payload 编码后失效的问题  

---

## ✅ 使用建议

```bash
python3 xs_scan.py -u http://example.com --cookie "SESSIONID=abc123"
```

## 运行截图

![image](https://github.com/user-attachments/assets/d99da47b-ce89-450d-a8e8-2e39c4c8fd8c)

![image](https://github.com/user-attachments/assets/1b7a9e34-894e-43d0-b43b-e52558c3d58b)

![image](https://github.com/user-attachments/assets/94d31010-83f9-42e3-850f-2af968c289c3)


## 🎯 未来计划预告

- 支持 DOM-based XSS 检测  
- 添加 URL 白名单与黑名单机制  
- 图形化界面（Web UI）开发中  

---

欢迎提出 Issue 与 PR，一起构建更强的 Web 安全工具！
