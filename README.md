# XJTU西安交大研究生体育自动打卡脚本

## 简介

此脚本用于西安交通大学研究生体美劳中体育打卡系统的自动签到与签退。脚本模拟用户登录，获取认证令牌，并在指定时间间隔后完成签到和签退操作，支持邮件通知功能。

---

## 环境配置

### 依赖安装

运行前需安装以下Python库：

```bash
pip install requests pycryptodome 
```

---

## 使用说明

### 1. 配置用户信息

打开脚本文件 sport_bot.py，修改以下字段：

- **学号与密码**  
  找到 `Config` 类中的变量：
  ```python
  USER = "user"         # 改为你的学号
  PASSWORD = "password"   # 改为你的密码
  ```

- **位置坐标**  
  默认使用涵英楼北草坪坐标，可自行修改：
  ```python
  LONGTITUDE = 108.654387      # 经度
  LATITUDE = 34.257229        # 纬度
  ```

---

### 2. 邮件通知配置（可选）

若需启用邮件通知，按以下步骤配置：

1. **开启QQ邮箱SMTP服务**  
   - 登录QQ邮箱 → 设置 → 账户 → 开启“POP3/SMTP服务”
   - 生成16位SMTP授权码（`auth_code`）

2. **修改脚本配置**  
   在 `Config` 类中设置：
   ```python
   SEND_EMAIL = True                # 设为True启用邮件通知
   SMTP_AUTH_CODE = "你的SMTP授权码"  # 从QQ邮箱获取
   EMAIL_SENDER = "发件人QQ邮箱@qq.com"
   EMAIL_RECEIVER = "接收通知的邮箱"  # 可以是同一邮箱
   ```

---

## 运行脚本

### 方法1：直接执行脚本：
```bash
python sport_bot.py
```

### 方法2：使用定时任务：
可使用系统工具（如cron或任务计划程序）设置定时运行，实现全自动打卡。

**在Linux系统中使用crontab定时运行脚本：**
1. 打开crontab编辑器：
   ```bash
   crontab -e
   ```
2. 添加定时任务（每天中午12点运行）：
   ```bash
   0 12 * * * /usr/bin/python3 /path/to/sport_bot.py
   ```
   注意替换`/usr/bin/python3`为你的Python解释器路径，`/path/to/sport_bot.py`为脚本的绝对路径。

若打卡失败，请检查日志文件 `sport_bot.log` 或根据邮件提示排查错误。

---

## 免责声明
此脚本仅供学习和交流使用，请勿用于任何商业用途或违反学校规定的行为。使用此脚本所产生的任何后果由使用者自行承担，作者不对任何损失或损害负责。请尊重他人劳动成果，合理使用技术手段。
