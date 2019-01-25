# -*- coding: utf-8 -*-
'''
@File  : newRun.py
@Date  : 2019/1/25/025 15:40
'''
from common.log import Log
from common.handleCase import HandleCase
from common.httputils import Http
from common.parseConfig import ParseConfig
from common.report import get_now

log = Log().getLog()
pc = ParseConfig()
cases = HandleCase().get_cases()
CASEID = "caseId"
APIID = "apiId"
CASEDESCRIBE = "caseDescribe"
APIHOST = "apiHost"
PARMAS = "params"
METHOD = "method"
HEADERS = "headers"
FACT = "fact"
EXPECT = "expect"
DATABASERESUTL = "databaseResult"
DATABASEEXPECT = "databaseExpect"
ISPASS = "ispass"
TIME = "time"
FORMORT = "%Y/%m/%d %H:%M:%S"
PASS="pass"
FAIL="fail"
REASON="reason"


def excute_case(case):
    global caseId, apiId, apiHost, params, method, headers
    if not case:
        log.error("没有可执行的用例")
        return
    if CASEID in case.keys():
        caseId = case[CASEID]
    if APIID in case.keys():
        apiId = case[APIID]
    if APIHOST in case.keys():
        apiHost = case[APIHOST]
    if PARMAS in case.keys():
        params = case[PARMAS]
    if METHOD in case.keys():
        method = case[METHOD]
    # 如果调用创建用户接口，不需要headers信息
    if apiHost == "/s5/create_user":
        headers = None
    else:
        headers = pc.get_info(HEADERS)
    log.info("此次接口请求的header信息为--->{}".format(headers))
    if method == "post":
        res = Http.post(apiHost, params=params, headers=headers)
    elif method == "get":
        res = Http.get(apiHost, params=params, headers=headers)
    else:
        log.error("ERRRR:暂不支持{}这种请求方式".format(method))
        # res = None
        return "ERRRR：暂不支持{}这种请求方式".format(method)
    # 如果调用创建用户或登录接口，将headers信息写入配置文件
    if apiHost == "/s5/create_user" or apiHost == "/s5/login.mobile" and res is not None:
        pc.wirte_info(HEADERS, HEADERS, res.headers["Set-Cookie"])
        log.info("headers信息写入配置文件成功--->{}".format(res.headers["Set-Cookie"]))
    return res


def get_report_data(caseID, apiId, caseDesciribe, apiHost,
                    apiParams, expect, fact,time, isPass="pass",reason="",databaseResutl="",databaseExpect=""):
    result = {}
    result[CASEID] = caseID
    result[APIID] = apiId
    result[CASEDESCRIBE] = caseDesciribe
    result[APIHOST] = apiHost
    result[PARMAS] = apiParams
    result[EXPECT] = expect
    result[FACT] = fact
    result[DATABASERESUTL] = databaseResutl
    result[databaseExpect] = databaseExpect
    result[ISPASS] = isPass
    result[TIME] = time
    result[REASON]=reason
    return result



def check(fact, expect, result):
    if "ERRRR" in fact:
        result[ISPASS]=FAIL
        result[REASON]=fact
        result[TIME] = get_now().strftime(FORMORT)
        return
    try:
        response=fact.json()
        temp=""
        if not expect:
            result[ISPASS] = "block"
            result[TIME] = get_now().strftime(FORMORT)
            result[REASON] = "检查点未设置"
            return
        for key in expect.keys():
            if not isinstance(expect[key], dict):
                # 判断检查点中的字段是否在响应结果中
                if key not in response.keys():
                    result["ispass"] = "fail"
                    result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
                    result["reason"] = "实际结果中没有{}这个字段,检查用例是否错误或接口返回结果错误".format(key)
                    return
                # 判断检查点中字段的值和返回结果字段的值是否一致
                if not str(expect[key]).__eq__(str(response[key])):
                    result["ispass"] = "fail"
                    result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
                    temp += "{}的值预期为：{}，实际为：{}\n".format(key, expect[key], response[key])
                    result["reason"] = temp
                else:
                    # 判断是否有检查点判断失败，如果有，ispass值仍然为fail
                    if result["ispass"].__eq__("fail"):
                        result["ispass"] = "fail"
                    else:
                        result["ispass"] = "pass"
                    result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
            # 判断双重检查点，例如payload.message的形式
            else:
                for key1 in expect[key].keys:
                    if str(response[key][key1]).__eq__(str(expect[key][key1])):
                        result["ispass"] = "fail"
                        result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
                        temp += "{}的值预期为：{}，实际为：{}\n".format(key, expect[key], response[key])
                        result["reason"] = temp
                    else:
                        result["ispass"] = "pass"
                        result["time"] = get_now().strftime("%Y/%m/%d %H:%M:%S")
    except Exception as e:
        print(e)





if __name__ == '__main__':
    for case in cases:
        res=excute_case(case)
        fact=get_report_data(case[CASEID],case[APIID],
                        case[CASEDESCRIBE],case[APIHOST],
                        case[PARMAS],case[EXPECT],res,get_now().strftime(FORMORT))
        check(res,"",result=fact)
        print(fact)
