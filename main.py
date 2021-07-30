import datetime
import logging
import os
import re
import time

import pandas as pd
import requests
import xmltodict
from config import Config as cfg

from Email import Email as email

logging.basicConfig(filename='CVE_search.log', level=logging.INFO,
                    format='%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s\n',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filemode='w')

try:
    with open('input.cfg', 'r', encoding='utf-8') as fp:
        config = cfg(fp)
except Exception as e:
    logging.error(str(e))
    raise e


def check_dict_path(d, *indices):
    sentinel = object()
    for index in indices:
        if d is None:
            return False
        d = d.get(index, sentinel)
        if d is sentinel:
            return False
    return True


def convert_dict2string(dict_line):
    ''':ivar 传入需要转换为字符串的字典（组）
    返回字符串，其中的单行字符串：1）如果key为‘@Title’，则值为变量名，返回{dic[key]}:;
    2）如果key为‘#text’，则值为变量值，返回{dic[key]}\n;
    3)如果key不为‘@Title’且key不为‘#text’，则当前键值对即包含了变量名与变量值，返回key:dic[key]\n
    '''
    temp_list = []
    output = ""
    if not isinstance(dict_line, list):
        temp_list.append(dict_line)
    else:
        temp_list = dict_line
    for each in temp_list:
        for key in each:
            if '@' not in key and '#text' != key:
                output = output + '%s:%s\n' % (key, each[key])
            elif '#text' == key:
                output = output + "%s\n" % (each[key])
            elif key == '@Title':
                output = output + "%s:" % (each[key])
    return output


def load_daily_xml():
    logging.info('Loading new cverf file:https://cve.mitre.org/data/downloads/allitems-cvrf-year-%s.xml' % str(
        datetime.datetime.now().timetuple()[0]))
    r = requests.get(
        'https://cve.mitre.org/data/downloads/allitems-cvrf-year-%s.xml' % str(datetime.datetime.now().timetuple()[0]),
        timeout=5)
    if r.status_code == 200:
        if not ('source' in os.listdir('.') and os.path.isdir('source')):
            os.mkdir('source')

        with open('source/' + 'allitems-cvrf-year-%s.xml' % str(datetime.datetime.now().timetuple()[0]), 'w',
                  encoding='utf-8') as fp:
            fp.write(r.text)
        return True
    else:
        raise RuntimeError(
            "status_code is not 200 from https://cve.mitre.org/data/downloads/allitems-cvrf-year-%s.xml" % str(
                datetime.datetime.now().timetuple()[0]))


def load_keywords():
    if config.get('keywords'):
        logging.info("所需配置键值对存在，读取cfg成功。")
    else:
        logging.error('input.cfg文件有键缺失。')
        raise RuntimeError('input.cfg文件有键缺失。')


def Is_today_cvrf(filepath):
    return time.strftime('%Y-%m-%d', time.localtime(os.stat(filepath).st_mtime)) == time.strftime('%Y-%m-%d',
                                                                                                  datetime.datetime.now().timetuple())


def initialize_result():
    global checked_cve
    if 'result.xlsx' in os.listdir('.'):
        logging.info('result.xlsx存在，有已有记录，追加记录。')
        before = pd.read_excel('result.xlsx')
        logging.info('已记录的CVE code:')
        checked_cve = list(before['CVE'])
        logging.info(checked_cve)
        return before
    else:
        logging.info('result.xlsx不存在。')
        return pd.DataFrame(columns=['CVE', 'Keyword', 'Notes', 'References', 'Record time'])


def initialize_newline(each_vul):
    ''':ivar 输入当前Vulnerability
    返回Record time:datetime(%Y-%m-%d %H:%M:%S),
        CVE:当前Vulnerability下的CVE
        Notes:当前Vulnerability下的Notes:Note
    '''
    return {'Record time': time.strftime("%Y-%m-%d %H:%M:%S", datetime.datetime.now().timetuple()),
            'CVE': each_vul['CVE'], 'Notes': convert_dict2string(each_vul['Notes']['Note']),
            'References': "", 'Keyword': ""}


def contains_keyword(line, keyword):
    return re.findall(re.compile("%s\W" % line, flags=re.I), keyword)


if __name__ == '__main__':
    load_keywords()

    file_path = 'source/' + 'allitems-cvrf-year-%s.xml' % str(datetime.datetime.now().timetuple()[0])
    logging.info('来源文件名：' + file_path)
    if not os.path.exists(file_path):
        load_daily_xml()
    else:
        if not Is_today_cvrf(file_path):
            load_daily_xml()

    with open(file_path, 'r') as fp:
        doc = xmltodict.parse(fp.read())

    checked_cve = []
    result = initialize_result()
    all_vul = []
    if check_dict_path(doc, 'cvrfdoc', 'Vulnerability'):
        all_vul.extend(doc['cvrfdoc']['Vulnerability'])

        for each_vul in all_vul:
            newline = initialize_newline(each_vul)
            if check_dict_path(each_vul, 'References', 'Reference'):
                newline['References'] = convert_dict2string(each_vul['References']['Reference'])
            for Keyword in config.get('keywords'):
                if contains_keyword(Keyword.upper(), newline['Notes'].upper()):
                    logging.info("在Note：'" + newline['Notes'] + "'中找到关键词：" + Keyword + "，CVE号：" + newline['CVE'])
                    if newline['CVE'] in checked_cve:
                        logging.info("CVE号：" + newline['CVE'] + "记录已有，不更新追加。")
                    else:
                        logging.info("CVE号：" + newline['CVE'] + "记录不存在，更新追加。")
                        newline['Keyword'] = Keyword
                        result = result.append(newline, ignore_index=True)

    result.to_excel('result.xlsx', index=None)
    email = email(config)
    email.addAttachment('result.xlsx')
    email.send_email()
