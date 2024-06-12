#!/usr/bin/env python3
import os
import subprocess
import json
import re
import base64
import tornado.escape
import tornado.ioloop
import tornado.web
import tornado.websocket
from urllib.parse import parse_qs
import requests
import traceback
import hashlib
import datetime
import logging
import coloredlogs

coloredlogs.install(level='DEBUG',
                    fmt='%(asctime)s %(filename)s[%(lineno)d] %(levelname)s: %(message)s',
                    milliseconds=True)

def load_config(file_path):
    with open(file_path, 'r') as f:
        config = json.load(f)
    return config

config = {"users":[],"auth":[]}
# 判断配置文件是否存在
if os.path.exists("access.json"):
    config = load_config("access.json")
else:
    with open("access.json", 'w') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def message_handler(message):
    # 在这里调用其他非异步函数执行动作，返回结果
    logging.debug(f"处理消息：{message}")
    result = f"消息处理完成：{message}"
    return result

def add_firewall_rule(ip):
    p = subprocess.Popen(["powershell.exe", "& D:\\pokebox\\workspace\\auto_firewall\\setFirewall.ps1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    out, err = p.communicate()
    out = out.decode("GBK")
    err = err.decode("GBK")
    logging.debug(f"out: {out}")
    logging.debug(f"err: {err}")
    if p.returncode == 0 and err == "":
        return str(out)
    else:
        return str("操作失败，可能是权限不足或者其他原因。您的IP地址" + ip + "已记录。")

def perform_action(message):
    # 在这里调用其他非异步函数执行动作，返回结果
    logging.debug(f"执行动作：{message}")
    result = f"动作执行完成：{message}"
    return result


class WebhookHandler(tornado.web.RequestHandler):
    def get(self):
        # 解析 URL 参数以获取 access_token
        query = self.request.query
        params = parse_qs(query)
        client_access_token = params.get("access_token", [None])[0]

        if client_access_token not in config["auth"]:
            self.set_status(403)
            self.write({"code": 403, "message": "Access Denied"})
            return

        logging.debug(f"收到来自 {self.request.remote_ip} 的 GET 请求, 参数：{params}")
        # 参数转换为字典对象
        params_dict = {}
        for key in params:
            params_dict[key] = params[key][0]
        logging.debug(f"收到来自 {self.request.remote_ip} 的 GET 请求, 参数：{params_dict}")
        ret = add_firewall_rule(self.request.remote_ip)
        
        self.set_status(200)
        retobj = {
            "code": 0,
            "message": "success",
            "ret": ret
        }
        self.write(retobj)

    def post(self):
        # 解析 URL 参数以获取 access_token
        logging.debug(f"收到来自 {self.request.remote_ip} 的 POST 请求, path: {self.request.path}")
        query = self.request.query
        logging.debug(f"query: {query}")
        params = parse_qs(query)
        client_access_token = params.get("access_token", [None])[0]
        logging.debug(f"client_access_token: {client_access_token}")
        try:
            content_type = self.request.headers.get("Content-Type", "")
            if content_type.startswith("application/json"):
                post_data = tornado.escape.json_decode(self.request.body)
            else:
                post_data = {}
            logging.debug(post_data)
            ## 验证token
            if client_access_token is None:
                # 从 header 中获取
                client_access_token = self.request.headers.get("Authorization", None)
                # 去掉前缀
                client_access_token = client_access_token.replace("Bearer ", "")
                logging.debug(f"client_access_token: {client_access_token}")
                logging.debug(f"headers: {self.request.headers}")
            
            config = load_config("access.json") #自动重读一次配置
            date = datetime.datetime.now().strftime('%Y%m%d%H%M')
            culist = str(config["users"][0]) + str(config["auth"][0]) + str(date)
            logging.info(f"culist: {culist}")
            md5val = hashlib.md5(culist.encode('utf-8')).hexdigest()
            logging.info(f"md5val: {md5val}")
            #md5验证
            if client_access_token is None or client_access_token != md5val:
            #if client_access_token not in config["auth"]:
                self.set_status(403)
                self.write({"code": 403, "message": "Access Denied"})
                logging.debug(f"收到来自 {self.request.remote_ip} 的 POST 请求，但 access_token 不正确")
                return
            
            # 在这里可以处理 POST 数据，调用其他函数执行动作等
            logging.debug(f"收到 POST 数据：{post_data}")
            #ret = message_handler(post_data)
            ret = add_firewall_rule(self.request.remote_ip)

            self.set_status(200)
            retobj = {
                "code": 0,
                "message": "success",
                "ret": ret
            }
            self.write(retobj)
        except:
            logging.error(traceback.format_exc())
            self.set_status(403)
            self.write({"code": 500, "message": "Error"})
            return


class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        logging.debug("WebSocket 连接已打开")

    def on_message(self, message):
        try:
            logging.debug(f"收到来自 {self.request.remote_ip} 的 WebSocket 消息：{message}")
            data = json.loads(message)
            if data.get("action") == "send_msg":
                if "message_type" in data.get("params"):
                    message_type = data.get("params").get("message_type")
                    if message_type == "group":
                        pass
                    elif message_type == "private":
                        message_handler(data.get("params"))
                    message = data.get("params").get("message")
                    user_id = data.get("params").get("user_id")

                    print(f"收到要发给 {user_id} 的消息：{message}")

                    # 调用其他函数执行动作
                    action_result = perform_action(message)

                    # 在这里可以对接收到的消息进行处理和回复
                    reply_data = {
                        "reply": action_result,
                        "at_sender": False
                    }

                    reply_message = json.dumps({
                        "action": "send_private_msg",
                        "params": {
                            "user_id": user_id,
                            "message": reply_data
                        }
                    })

                    self.write_message(reply_message)

        except json.JSONDecodeError as e:
            print("无法解析 JSON 数据:", e)

    def on_close(self):
        logging.debug("WebSocket 连接已关闭")


def make_a_new_app():
    return tornado.web.Application([
        (r"/.*", WebhookHandler),
        (r"/ws", WebSocketHandler)
    ], **{"port": int(config["webhook_port"])},debug=False)

def make_app():
    webhook_app = tornado.web.Application([
        (r"/.*", WebhookHandler),
    ], **{"port": int(config["webhook_port"])},debug=True)

    websocket_app = tornado.web.Application([
        (r"/.*", WebSocketHandler),
    ], **{"port": int(config["websocket_port"])},debug=True)

    return webhook_app, websocket_app

if __name__ == "__main__":
    if True:
        app = make_a_new_app()
        app.listen(app.settings["port"])
    else:
        webhook_app, websocket_app = make_app()
        webhook_app.listen(webhook_app.settings["port"])
        websocket_app.listen(websocket_app.settings["port"])

    tornado.ioloop.IOLoop.current().start()