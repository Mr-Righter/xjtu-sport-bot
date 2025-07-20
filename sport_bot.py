#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XJTU运动打卡自动化脚本

功能描述:
- 自动登录西安交通大学CAS认证系统
- 执行体育锻炼签到和签退操作
- 支持邮件通知功能
- 完整的日志记录和错误处理

依赖库:
- requests: HTTP请求库
- beautifulsoup4: HTML解析库
- pycryptodome: 加密库（用于RSA密码加密）

使用方法:
1. 修改Config类中的用户信息和坐标
2. （可选）配置邮件通知功能
3. 运行脚本: python sport_bot.py

作者: Mr-Righter
版本: 2.0
最后更新: 2025-07-20
"""

import requests
import logging
import time
import base64
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


# -------------------- 配置类 --------------------
class Config:
    """
    程序配置类

    请根据实际情况修改以下配置项
    """

    # ========== 用户信息配置 ==========
    USER = "Student_Id"  # 学号/工号
    PASSWORD = "Password"  # 登录密码（请及时修改为您的实际密码）

    # ========== 地理位置配置 ==========
    # 涵英楼北草坪坐标（可根据实际锻炼地点修改）
    LONGITUDE = 108.654387  # 经度
    LATITUDE = 34.257229  # 纬度

    # ========== 邮件通知配置 ==========
    SEND_EMAIL = True  # 是否启用邮件通知功能
    SMTP_AUTH_CODE = "auth_code"  # QQ邮箱SMTP授权码
    EMAIL_SENDER = "your_qq_email"  # 发件人邮箱地址
    EMAIL_RECEIVER = "your_qq_email"  # 接收通知的邮箱地址

    # ========== 日志配置 ==========
    LOG_FILE = os.path.join(os.path.dirname(__file__), "sport_bot.log")
    LOG_LEVEL = logging.INFO  # 日志级别: DEBUG, INFO, WARNING, ERROR

    # ========== 系统配置（通常无需修改）==========
    APP_ID = "1740"  # 应用ID
    REDIR = "https://ipahw.xjtu.edu.cn/sso/callback"  # 回调URL
    STATE = "1234"  # OAuth状态参数

    # 用户代理字符串
    UA = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    )

    # API端点
    OPEN_OAUTH = "https://org.xjtu.edu.cn/openplatform/oauth/authorize"
    CAS_PUBKEY = "https://login.xjtu.edu.cn/cas/jwt/publicKey"
    CODE_LOGIN = "https://ipahw.xjtu.edu.cn/szjy-boot/sso/codeLogin"

    # 签到签退API端点
    SIGN_IN_URL = "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signRun"
    SIGN_OUT_URL = "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signOutTrain"


# -------------------- 初始化日志 --------------------
def setup_logging():
    """设置日志配置，同时输出到控制台和文件"""
    logger = logging.getLogger()
    logger.setLevel(Config.LOG_LEVEL)

    # 清除已有的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # 创建格式器
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 文件处理器
    file_handler = logging.FileHandler(Config.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


# 初始化日志系统
setup_logging()


# -------------------- 工具函数 --------------------
def rsa_encrypt(pwd: str, pem: str) -> str:
    """
    Encrypt password using RSA public key

    Args:
        pwd (str): Password to be encrypted
        pem (str): RSA public key in PEM format

    Returns:
        str: Encrypted password with format "__RSA__" + base64 encoded string
    """
    try:
        cipher = PKCS1_v1_5.new(RSA.import_key(pem))
        encrypted = base64.b64encode(cipher.encrypt(pwd.encode())).decode()
        return "__RSA__" + encrypted
    except Exception as e:
        logging.error(f"密码加密失败: {str(e)}")
        raise


def extract_form_inputs(html: str, form_selector: str = "form#fm1") -> dict:
    """
    Extract form input field names and values from HTML content

    Args:
        html (str): HTML content string
        form_selector (str): CSS selector to locate the form, defaults to "form#fm1"

    Returns:
        dict: Dictionary containing input field names and values

    Raises:
        ValueError: Raised when no form is found
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        form = soup.select_one(form_selector) or soup.select_one("form")

        if not form:
            raise ValueError(f"未找到表单，选择器: {form_selector}")

        data = {}
        for inp in form.select("input[name]"):
            # Skip unchecked checkboxes (like rememberMe checkbox)
            if inp.get("type") == "checkbox":
                continue

            name = inp.get("name")
            value = inp.get("value", "")
            if name:
                data[name] = value

        logging.debug(f"提取到 {len(data)} 个表单字段")
        return data

    except Exception as e:
        logging.error(f"表单字段提取失败: {str(e)}")
        raise


def get_token(user, password):
    """
    Get access token through CAS login process

    Args:
        user (str): Username (student ID)
        password (str): Password

    Returns:
        str: Access token, returns None if failed
    """
    try:
        sess = requests.Session()
        sess.headers.update(
            {
                "User-Agent": Config.UA,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
            }
        )

        # Step 1: openplatform -> CAS /authorize
        r0 = sess.get(
            Config.OPEN_OAUTH,
            params={
                "appId": Config.APP_ID,
                "redirectUri": Config.REDIR,
                "responseType": "code",
                "scope": "user_info",
                "state": Config.STATE,
            },
            allow_redirects=False,
            headers={"Referer": Config.REDIR.rsplit("/", 1)[0] + "/"},
        )
        cas_auth = r0.headers["Location"]

        # Step 2: /authorize -> /login (get SESSION)
        cas_login = sess.get(cas_auth, allow_redirects=False).headers["Location"]

        # Step 3: GET login page
        page = sess.get(cas_login).text
        form_data = extract_form_inputs(page)

        # Step 4: RSA encrypt password
        form_data.update(
            {
                "username": user,
                "password": rsa_encrypt(password, sess.get(Config.CAS_PUBKEY).text),
                # 需要勾选 “记住我” 就把下一行取消注释
                # "rememberMe": "on",
            }
        )

        # Step 5: POST login data
        r_post = sess.post(
            cas_login,
            data=form_data,
            headers={
                "Origin": "https://login.xjtu.edu.cn",
                "Referer": cas_login,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            allow_redirects=False,
        )

        # Step 6: Follow callback chain to business system
        final = sess.get(r_post.headers["Location"], allow_redirects=True)
        qs = parse_qs(urlparse(final.url).query)
        params = {k: v[0] for k, v in qs.items()}

        # Step 7: Get sign-in/sign-out token
        response = requests.get(
            Config.CODE_LOGIN,
            headers={
                "User-Agent": Config.UA,
                "Referer": final.url,
            },
            params=params,
        )

        token = response.json()["data"]["token"]
        return token

    except Exception as e:
        logging.error(f"获取访问令牌失败: {str(e)}")
        return None


def sign_operation(url: str, payload: dict, token: str, operation_name: str) -> bool:
    """
    Execute sign-in or sign-out operation

    Args:
        url (str): Request URL
        payload (dict): Request payload data
        token (str): Access token
        operation_name (str): Operation name (for logging)

    Returns:
        bool: Whether the operation was successful
    """
    logging.info(f"开始执行{operation_name}操作")

    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/537.36",
                "token": token,
            },
            data=json.dumps(payload),
            timeout=30,  # Add timeout setting
        )

        logging.info(f"{operation_name}请求状态码: {response.status_code}")

        if response.status_code == 200:
            try:
                response_data = response.json()
                if response_data.get("success"):
                    logging.info(f"{operation_name}操作成功")
                    return True
                else:
                    error_msg = response_data.get("msg", "未知错误")
                    logging.warning(f"{operation_name}操作失败: {error_msg}")
                    return False
            except json.JSONDecodeError:
                logging.error(
                    f"{operation_name}响应JSON解析失败: {response.text[:200]}"
                )
                return False
        else:
            logging.error(f"{operation_name}请求失败，状态码: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        logging.error(f"{operation_name}请求超时")
        return False
    except requests.exceptions.RequestException as e:
        logging.error(f"{operation_name}网络请求异常: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"{operation_name}操作异常: {str(e)}")
        return False


def send_email(content: str) -> bool:
    """
    Send email notification

    Args:
        content (str): Email content

    Returns:
        bool: Whether the sending was successful
    """
    if not Config.SEND_EMAIL:
        logging.debug("邮件发送功能已禁用")
        return True

    logging.info("开始发送邮件通知")

    try:
        # Create email object
        msg = MIMEText(content, "plain", "utf-8")
        msg["From"] = Header(Config.EMAIL_SENDER)
        msg["To"] = Header(Config.EMAIL_RECEIVER)
        msg["Subject"] = Header("XJTU运动打卡通知", "utf-8")

        # Send email
        with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=30) as smtp:
            smtp.login(Config.EMAIL_SENDER, Config.SMTP_AUTH_CODE)
            smtp.sendmail(Config.EMAIL_SENDER, [Config.EMAIL_RECEIVER], msg.as_string())

        logging.info("邮件发送成功")
        return True

    except smtplib.SMTPAuthenticationError:
        logging.error("邮件发送失败: SMTP认证失败，请检查邮箱和授权码")
        return False
    except smtplib.SMTPException as e:
        logging.error(f"邮件发送失败: SMTP错误 - {str(e)}")
        return False
    except Exception as e:
        logging.error(f"邮件发送失败: {str(e)}")
        return False


def main():
    """
    Main function: Execute complete sports check-in process
    """
    logging.info("=" * 50)
    logging.info("XJTU运动打卡程序启动")
    logging.info("=" * 50)

    try:
        # Get access token
        logging.info("步骤1: 获取访问令牌")
        token = get_token(Config.USER, Config.PASSWORD)

        if not token:
            error_msg = "获取访问令牌失败，请检查网络连接和账号密码"
            logging.error(error_msg)
            if Config.SEND_EMAIL:
                send_email(f"运动打卡失败\n\n{error_msg}")
            return False

        logging.info("访问令牌获取成功")

        # Execute sign-in operation
        logging.info("步骤2: 执行签到操作")
        sign_in_payload = {
            "sportType": 2,
            "longitude": Config.LONGITUDE,
            "latitude": Config.LATITUDE,
            "courseInfoId": "null",
        }

        sign_in_success = sign_operation(
            Config.SIGN_IN_URL,
            sign_in_payload,
            token,
            "签到",
        )

        if sign_in_success:
            logging.info("签到成功！开始等待31分钟后自动签退...")
            print("签到成功！请勿关闭程序，31分钟后自动签退...")

            # Wait for 31 minutes
            wait_time = 31 * 60  # 31 minutes (in seconds)
            logging.info(f"等待{wait_time}秒（31分钟）后执行签退")

            time.sleep(wait_time)

            # Execute sign-out operation
            logging.info("步骤3: 执行签退操作")
            sign_out_payload = {
                "longitude": Config.LONGITUDE,
                "latitude": Config.LATITUDE,
            }

            sign_out_success = sign_operation(
                Config.SIGN_OUT_URL,
                sign_out_payload,
                token,
                "签退",
            )

            if sign_out_success:
                success_msg = "运动打卡完成！签到和签退都已成功"
                logging.info(success_msg)
                print(success_msg)

                if Config.SEND_EMAIL:
                    send_email(
                        "XJTU运动打卡成功\n\n签到和签退操作均已完成，本次打卡有效！"
                    )
                return True
            else:
                warning_msg = "签到成功但签退失败，请手动进行签退操作"
                logging.warning(warning_msg)
                print(warning_msg)

                if Config.SEND_EMAIL:
                    send_email(f"XJTU运动打卡部分成功\n\n{warning_msg}")
                return False
        else:
            error_msg = "签到失败，请检查网络连接或稍后重试"
            logging.error(error_msg)
            print(f"签到失败！请查看日志文件 {Config.LOG_FILE} 获取详细错误信息")

            if Config.SEND_EMAIL:
                send_email(f"XJTU运动打卡失败\n\n{error_msg}")
            return False

    except KeyboardInterrupt:
        logging.warning("程序被用户中断")
        print("\n程序被用户中断")
        return False
    except Exception as e:
        error_msg = f"程序执行过程中发生未预期的错误: {str(e)}"
        logging.error(error_msg)
        print(f"程序执行出错！请查看日志文件 {Config.LOG_FILE} 获取详细信息")

        if Config.SEND_EMAIL:
            send_email(f"XJTU运动打卡程序异常\n\n{error_msg}")
        return False
    finally:
        logging.info("XJTU运动打卡程序结束")
        logging.info("=" * 50)


if __name__ == "__main__":
    main()
