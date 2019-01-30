# -*- coding: utf-8 -*-
'''
@File  : temp.py
@Date  : 2019/1/22/022 15:37
'''
# if relatedApi is None:
#     if method == "post":
#         fact = Http.post(host, params=params, headers=headers)
#         result["fact"] = str(fact.text)
#         check(checkPints, fact, result)
#         # 如果是第一条用例，则将headers信息写入配置文件
#         if is_first_case:
#             write_headers((str(fact.headers["Set-Cookie"])))
#     elif method == "get":
#         fact = Http.get(host, params=params, headers=headers)
#         result["fact"] = str(fact.text)
#         check(checkPints, fact, result)
#         if is_first_case:
#             write_headers((lambda s: s.replace("\'", "\""))(str(fact.headers)))
#     else:
#         result["fact"] = "用例请求方法错误"
#         result["ispass"] = "fail"
#         result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
#         result["reason"] = "用例错误，无法执行，没有{}请求方法".format(method)
#         log.error("没有{}这种请求方式,请修改用例".format(method))
#     result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
# else:
#     # temp=con.query_one("select * from apiInfo where apiId={}".format(relatedApi))

import string
import json

# s=string.Template("$name is $age")
# name="zs"
# age=10
# s=s.substitute(vars())
# print(s)
import threading

from common.parseConfig import ParseConfig
from common.parseExc import PaserExc
from common.report import Report
import os
import re
# path = os.path.abspath(__file__).replace("temp.py", "cases")
# dir_name = os.listdir(path)
# print(os.path.abspath("."))
# for i in dir_name:
#     extension = os.path.splitext(i)[1]
#     if extension == ".xlsx":
#         print("{}--{}".format(i,True))
#     else:
#         print("{}--{}".format(i,False))
# rep=re.compile(r"^case_")
# report=Report()
# print(os.access(report.reportPath,os.F_OK))
from common.conDatabase import ConMysql
con=ConMysql()
s=con.query_one("select * from testresult")
print(type(s))
import json
s["time"]="2019/1/30 11:19:10"
print(s)
print(json.dumps(s,ensure_ascii=False))

