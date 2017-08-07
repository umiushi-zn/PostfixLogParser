# -*- coding: utf-8 -*-
# for Python 3.4
# PostfixLogParser
# Version : 0.0.5a
# License : GPLv3
# (c) umiushi.zn@gmail.com
# Postfixのログを1行1ログに変換します。
# 手元の環境では18万行(15000レコードくらい)を約7秒で解析します。
#
# 依存
# pip install python-geoip
# pip install python-geoip-geolite2
#
# python3 PostfixLogParser.py
#  --inputs=/var/log/maillog*.gz --outputdir=export --compressed=Y --year=2017 --export-type=TSV
#
#  inputs      : 解析対象とするログファイルを指定してください
#  outputdir   : 指定したディレクトリに、解析結果が元ファイルの名称に「.txt」付与されて保存されます。
#                ディレクトリは予め作成しておいてください。
#  year        : ログには年号が記録されていないため年号(西暦)を数字で入れてください
#  compressed  : ファイルが圧縮(gzip)されている場合に指定してください。
#  export-type : TSV or JSON or ORIG
#                TSVはカラムの区切りをTabで出力します。
#                JSONは行ごとにJSON形式で出力されます。
#                ORIGはgrepし易いような形式で出力します。
import re
import argparse
import datetime
import glob
import os
import logging
import json
from abc import ABCMeta, abstractmethod

# LOGGING LEVEL
LOGGING_LEVEL = logging.INFO
# Using cProfile.
PROFILE_FLAG = False
# Buffer
WRITE_BUFFER = 1000000


def remove_char(src, replace):
    """
    特定文字列を削除します。
    引数に文字列を指定された場合は、1文字づつ空文字でreplaceを行います。
    配列を指定された場合は配列ごとに空文字でreplaceを行います。
    :param src:     対象文字列
    :param replace: 削除する文字(Listか文字列)
    :return:        削除後の文字列
    """

    for s in replace:
        src = src.replace(s, "")
    return src


class MaillogParser:
    """
    メールログをパースするクラスです。
    """
    re_date = r'(?P<month>[A-Z][a-z][a-z])  ?(?P<day>\d+) (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})'
    re_host = r'(?P<host>[^ ]*)'
    re_proc = r'(?P<proc>\w+)'
    re_qid = r'(?P<queue_id>[0-9A-F]+)'
    re_msg = r'(?P<message>.*)'
    re_line = r'^%s %s postfix/%s\[\d+\]: %s:\s*%s' % (re_date, re_host, re_proc, re_qid, re_msg)
    _month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def __init__(self, fn, year=None):
        """
        解析対象のログファイル名を指定してください。ログに年が記録されていないため
        年を手動で指定してください。年を指定しない場合は現在日付を使用します。
        :param fn:      ファイル名
        :param year:    年
        """
        self._filepath = fn
        self._file_object = None
        self._parse_starttime = None
        # メールログ格納要
        self._imlogs = {}
        # 年
        self._year = year
        if self._year is None:
            self._year = datetime.date.today().year
        # 圧縮ファイルかどうか
        self._compressed = False
        # 解析が終了したレコードの件数
        self._cnt_parse_end = 0
        self._pop_parsed_line = False  # popしないほうが早い

    @property
    def pop_parsed_line(self):
        """
        パース済みの行を削除するかパースした結果を他に利用したい場合はFalseで
        :return: 削除する場合はTrue, 削除しない場合はFalse
        """
        return self._pop_parsed_line

    @pop_parsed_line.setter
    def pop_parsed_line(self, value):
        """
        パース済みの行を削除するか
        :param value: True or False
        :return: なし
        """
        if value:
            self._pop_parsed_line = True
        else:
            self._pop_parsed_line = False

    @property
    def parsed_count(self):
        """
        解析済みメールログの行数を返します。qmgrプロセスがメールを
        removedした段階でカウントアップされます。
        :return: 解析済みメールログの行数
        """
        return self._cnt_parse_end

    @property
    def year(self):
        """
        設定されている西暦を返します。
        :return: 西暦
        """
        return self._year

    @year.setter
    def year(self, value):
        """
        年を西暦で指定してください。
        :param value: 年
        """
        self._year = value
        if self._year is None:
            self._year = datetime.date.today().year

    @property
    def filepath(self):
        """
        解析対象ログファイルのパスを返します。
        :return: 解析対象のファイルパス
        """
        return self._filepath

    @filepath.setter
    def filepath(self, value):
        """
        解析対象ログファイルのパスを指定してください。
        :param value: ファイルパス
        """
        self._filepath = value

    @property
    def compressed(self):
        """
        解析対象のログファイルを圧縮ファイルとして指定しているか
        TrueかFalseの値を返します。
        :return:
        """
        return self._compressed

    @compressed.setter
    def compressed(self, value):
        """
        解析対象のログファイルが圧縮ファイルか指定します。
        :param value: True/False
        """
        if value:
            self._compressed = True
        else:
            self._compressed = False

    # メールログDictionaryの初期化
    @staticmethod
    def _create_mlog():
        """
        メールログを格納するDictionaryオブジェクトの雛形を返します。
        :return: メールログの雛形
        """
        return {"host": "", "proc": [], "queue_id": "", "date_start_date": None,
                "date_end_date": None, "client_host": "", 'client_ip': "", 'message_id': "",
                "parse_end": False, "size": 0, "envelope_from": "", "envelope_to": [],
                "nrcpt": 0, "orig_to": [], "dsn": [], "status": [],
                "delay": 0.0, "delay_before_qmanager": 0.0, "delay_qmanager": 0.0,
                "delay_con_setup": 0.0, "delay_msg_trans": 0.0, "relay_host": [],
                "relay_ip": [], "relay_port": [], "smtp_message": []}

    @staticmethod
    def _parse_smtpd_line(ml, store):
        """
        smtpd行(スペースで分割済み)をパースする
        smtpd行には接続元のホスト名とIPアドレスが含まれるが、その他の情報も多いため
        文字列「client」がなければ無視する

        :param ml:      _create_mlogで作成されたメールログの雛形
        :param store:   client={HOSTNAME}[{IP_ADDRESS}] の形式をした文字列
        :return: なし
        """
        t_ary = store.split('=')
        # client部分の解析
        if len(t_ary) == 2 and t_ary[0] == 'client':
            cl = re.search(r'(?P<hostname>[^\[]*)\[(?P<ip>[^\]]*)\]', t_ary[1])
            if cl:
                ml["client_host"] = cl.group('hostname')
                ml["client_ip"] = cl.group('ip')
        return

    @staticmethod
    def _parse_cleanup_line(ml, store):
        """
        cleanup行(スペースで分割済み)をパースする
        cleanup行にはmessage_idが含まれる
        :param ml:      _create_mlogで作成されたメールログの雛形
        :param store:   message-id=<{MESSAGE_ID}> の形式をした文字列
        :return: なし
        """
        t_ary = store.split('=')
        # message-id部分の解析
        if len(t_ary) == 2 and t_ary[0] == "message-id":
            if t_ary[1] != '<>':
                t_ary[1] = remove_char(t_ary[1], '<>')
            ml["message_id"] = t_ary[1]
        return

    def _parse_qmgr_line(self, ml, store):
        """
        qmgr行(スペースで分割済み)をパースする
        :param ml:      _create_mlogで作成されたメールログの雛形
        :param store:   下記のいずれかの形式をした文字列
            removed
            from=<{ENVELOPE-FROM}>,
            size={MESSAGE_SIZE}
            nrcpt={RCPT_COUNT}
        :return:        qmgrからremoveされたときにTrueを返す
        """
        if store == 'removed':
            # qmgrから削除された場合は、処理を完了したものとみなす
            ml["parse_end"] = True
            self._cnt_parse_end += 1
            # logging.debug("{0}".format(self._cnt_parse_end))
            return True

        else:
            t_ary = store.split('=')
            if len(t_ary) == 2:
                # size
                if t_ary[0] == 'size':
                    try:
                        ml["size"] += int(t_ary[1])

                    except ValueError as ve:
                        logging.warning("size をintに変換できませんでしたが、無視します - {0}".format(ve))

                # from
                elif t_ary[0] == 'from':
                    # <>を取り除く
                    if t_ary[1] != '<>':
                        t_ary[1] = remove_char(t_ary[1], '<>')
                    ml["envelope_from"] = t_ary[1]

                # nrcpt
                elif t_ary[0] == 'nrcpt':
                    tmp = t_ary[1].split(' ')
                    try:
                        ml["nrcpt"] += int(tmp[0])

                    except ValueError as ve:
                        logging.warning("nrcpt をintに変換できませんでしたが、無視します - {0}".format(ve))

            return False

    @staticmethod
    def _parse_smtp_line(ml, store):
        """
        smtp行(スペースで分割済み)をパースする
            to=<{ENVELOPE_TO}>
            orig_to=<{ORIGINAL_TO}>
            relay={RELAYHOST}[{RELAY_IP}]:{RELAY_PORT}
            delay={DELAY}
            delays={BEFORE_QMGR}/{QMGR}/{SETUP}/{TRANS}
            dsn={DSN}
            status={STATUS}
        :param ml: 解析中のメールログディクショナリ
        :param store: スペースで分割済みのkey=value形式の文字列
        :return: Void
        """
        t_ary = store.split('=')
        if len(t_ary) >= 2:
            # orig_to
            if t_ary[0] == 'orig_to':
                if t_ary[1] != '<>':
                    t_ary[1] = remove_char(t_ary[1], '<>')
                ml["orig_to"].append(t_ary[1])

            # dsn
            elif t_ary[0] == 'dsn':
                ml["dsn"].append(t_ary[1])

            # status
            elif t_ary[0] == 'status':
                tmp = t_ary[1].split(" ")
                ml["status"].append(tmp[0])
                ml["smtp_message"].append(" ".join(tmp[1:]))

            # delay
            elif t_ary[0] == 'delay':
                try:
                    ml["delay"] += float(t_ary[1])

                except ValueError as ve:
                    logging.warning("delayをfloatに変換できませんでしたが、無視します - {0}".format(ve))

            # delays
            elif t_ary[0] == 'delays':
                tmp = t_ary[1].split('/')
                if len(tmp) == 4:
                    try:
                        tmbefore = float(tmp[0])
                        tm_qmng = float(tmp[1])
                        tm_setup = float(tmp[2])
                        tm_trans = float(tmp[3])

                        if ml["delay_before_qmanager"] < tmbefore:
                            ml["delay_before_qmanager"] = tmbefore

                        if ml["delay_qmanager"] < tm_qmng:
                            ml["delay_qmanager"] = tm_qmng

                        if ml["delay_con_setup"] < tm_setup:
                            ml["delay_con_setup"] = tm_setup

                        if ml["delay_msg_trans"] < tm_trans:
                            ml["delay_msg_trans"] = tm_trans

                    except ValueError as ve:
                        logging.warning("delaysをfloatに変換できませんでしたが、無視します - {0}".format(ve))

            # to
            elif t_ary[0] == 'to':
                # <>を取り除く
                if t_ary[1] != '<>':
                    t_ary[1] = remove_char(t_ary[1], '<>')
                ml["envelope_to"].append(t_ary[1])

            # relay
            elif t_ary[0] == 'relay':
                # ホスト名、IPアドレス、ポート番号を取得
                rly = re.search(r'(?P<host>[^\[]*)\[(?P<ip>[^\]]*)\]:(?P<port>[0-9]*)', t_ary[1])
                if rly:
                    ml["relay_host"].append(rly.group('host'))
                    ml["relay_ip"].append(rly.group('ip'))
                    ml["relay_port"].append(rly.group('port'))

                # 取得できないときはそのまま代入
                else:
                    ml["relay_host"].append(t_ary[1])
        return

    @staticmethod
    def _parse_local_line(ml, store):
        """
        local行(スペースで分割済み)をパースする
            to=<{ENVELOPE_TO}>
            orig_to=<{ORIGINAL_TO}>
            relay={RELAYHOST}[{RELAY_IP}]:{RELAY_PORT}
            delay={DELAY}
            delays={BEFORE_QMGR}/{QMGR}/{SETUP}/{TRANS}
            dsn={DSN}
            status={STATUS}
        :param ml: 解析中のメールログディクショナリ
        :param store: スペースで分割済みのkey=value形式の文字列
        :return: Void
        """
        t_ary = store.split('=')
        if len(t_ary) == 2:
            # orig_to
            if t_ary[0] == 'orig_to':
                # <>を取り除く
                # addr = t_ary[1]
                if t_ary[1] != '<>':
                    t_ary[1] = remove_char(t_ary[1], '<>')
                ml["orig_to"].append(t_ary[1])

            # dsn
            elif t_ary[0] == 'dsn':
                ml["dsn"].append(t_ary[1])

            # status
            elif t_ary[0] == 'status':
                tmp = t_ary[1].split(' ')
                ml["status"].append(tmp[0])
                ml["smtp_message"].append(" ".join(tmp[1:]))

            # delay
            elif t_ary[0] == 'delay':
                try:
                    ml["delay"] += float(t_ary[1])

                except ValueError as ve:
                    logging.warning("delayをfloatに変換できませんでしたが、無視します - {0}".format(ve))

            # delays
            elif t_ary[0] == 'delays':
                tmp = t_ary[1].split('/')
                if len(tmp) == 4:
                    try:
                        tmbefore = float(tmp[0])
                        tm_qmng = float(tmp[1])
                        tm_setup = float(tmp[2])
                        tm_trans = float(tmp[3])

                        if ml["delay_before_qmanager"] < tmbefore:
                            ml["delay_before_qmanager"] = tmbefore

                        if ml["delay_qmanager"] < tm_qmng:
                            ml["delay_qmanager"] = tm_qmng

                        if ml["delay_con_setup"] < tm_setup:
                            ml["delay_con_setup"] = tm_setup

                        if ml["delay_msg_trans"] < tm_trans:
                            ml["delay_msg_trans"] = tm_trans

                    except ValueError as ve:
                        logging.warning("delaysをfloatに変換できませんでしたが、無視します - {0}".format(ve))

            # to
            elif t_ary[0] == 'to':
                # <>を取り除く
                if t_ary[1] != '<>':
                    t_ary[1] = remove_char(t_ary[1], '<>')

                ml["envelope_to"].append(t_ary[1])

            # relay
            elif t_ary[0] == 'relay':
                # ホスト名、IPアドレス、ポート番号を取得
                rly = re.search(r'(?P<host>[^\[]*)\[(?P<ip>[^\]]*)\]:(?P<port>[0-9]*)', t_ary[1])
                if rly:
                    ml["relay_host"].append(rly.group('host'))
                    ml["relay_ip"].append(rly.group('ip'))
                    ml["relay_port"].append(rly.group('port'))

                # 取得できないときはそのまま代入
                else:
                    ml["relay_host"].append(t_ary[1])
        return

    def _dateparse(self, s) -> datetime.datetime:
        """
        ログ日付から日付オブジェクトを生成
        戻りはdatetime.datetime
        :param s:
        :return:
        """
        try:
            return datetime.datetime(
                self._year,
                self._month.index(s.group('month')) + 1,
                int(s.group('day')),
                int(s.group('hour')),
                int(s.group('minute')),
                int(s.group('second')))

        except IndexError as ie:
            raise ValueError("DateParse Error:{0}".format(ie))

        except ValueError as ve:
            raise ValueError("DateParse Error:{0}/{1}/{2} {3}:{4}:{5} - {6}".format(
                self._year,
                s.group('month'),
                s.group('day'),
                s.group('hour'),
                s.group('minute'),
                s.group('second'),
                ve
            ))

        except TypeError as te:
            raise TypeError("DateParse Error:{0}/{1}/{2} {3}:{4}:{5} - {6}".format(
                self._year,
                s.group('month'),
                s.group('day'),
                s.group('hour'),
                s.group('minute'),
                s.group('second'),
                te
            ))

    def parse(self):
        """
        メールログをパースします。
        :return:
        """
        pat_postfix = re.compile(self.re_line)
        # ファイルを読み取り専用で開く
        if self._compressed:
            import gzip
            # 圧縮ファイルは圧縮ファイルとして読み取る
            logging.info("圧縮ファイルとして処理を実行します。")
            try:
                self._file_object = gzip.open(self.filepath, 'rt')
            except IOError as ioe:
                raise IOError("Inputファイルを開けませんでした。{0}".format(ioe))
        else:
            # 普通のテキスト
            logging.info("非圧縮ファイルとして処理を実行します。")
            try:
                self._file_object = open(self.filepath, 'rt')
            except IOError as ioe:
                raise IOError("Inputファイルを開けませんでした。{0}".format(ioe))

        for row in self._file_object:
            # 行をパースする(date, host, proc, queue_id, message)
            s = pat_postfix.search(row)
            # マッチした場合のみ処理を行う
            if s:
                proc = s.group('proc')  # groupで何度も直接参照すると遅い
                # プロセスが smtpd、cleanup、qmgr、smtp, local の場合は下記の処理を実行する
                if proc == 'smtpd' or proc == 'cleanup' or proc == 'qmgr' or proc == 'smtp' or proc == 'local':

                    # 既存の解析済みログに含まれるか確認する
                    qid = s.group('queue_id')
                    skey = "{0}/{1}".format(s.group("host"), qid)
                    if skey in self._imlogs:
                        ml = self._imlogs[skey]
                    else:
                        ml = self._create_mlog()
                        ml["queue_id"] = qid
                        self._imlogs[skey] = ml

                    # 日付(strptimeの処理コストが高いため変更) - 0.4
                    dt = self._dateparse(s)
                    if ml["date_start_date"] is None:
                        ml["date_start_date"] = dt
                        ml["date_end_date"] = dt
                    elif ml["date_end_date"] < dt:
                        ml["date_end_date"] = dt
                    elif ml["date_start_date"] > dt:
                        ml["date_start_date"] = dt

                    # プロセス
                    ml["proc"].append(proc)

                    # ホスト名
                    ml["host"] = s.group('host')

                    # プロセスがsmtpdだった場合の処理
                    if proc == 'smtpd':
                        for store in s.group('message').split(", "):
                            self._parse_smtpd_line(ml, store)

                    # プロセスがcleanupだった場合の処理
                    elif proc == 'cleanup':
                        for store in s.group('message').split(", "):
                            self._parse_cleanup_line(ml, store)

                    # プロセスがqmgrだった場合の処理
                    elif proc == 'qmgr':
                        for store in s.group('message').split(", "):
                            if self._parse_qmgr_line(ml, store):
                                yield ml
                                # 不要になった配列を削除する
                                if self._pop_parsed_line:
                                    self._imlogs.pop(skey)

                    # プロセスがsmtpだった場合の処理
                    elif proc == 'smtp':
                        for store in s.group('message').split(", "):
                            self._parse_smtp_line(ml, store)

                    # プロセスがlocalだった場合の処理
                    elif proc == 'local':
                        for store in s.group('message').split(", "):
                            self._parse_local_line(ml, store)

                            # プロセスがPickupだった場合は無視(uidが必要な場合は解析する)
                            # elif s.group('proc') == 'pickup':
                            # pass

                            # プロセスがscacheだった場合は無視
                            # 下記の情報が有用だった場合は追加で解析する
                            # domain lookup hits=x miss=x success=x%
                            # address lookup hits=x miss=x success=x%
                            # max simultaneous domains=x addresses=x connection=x
                            # elif s.group('proc') == 'scache':
                            #    pass

                            # elif s.group('proc') == 'anvil':
                            #    pass

                            # elif s.group('proc') == 'trivial-rewrite':
                            #    pass

                            # else:
                            #    pass
            else:
                pass

        self._file_object.close()
        return

    def get_noncomplete_maillog(self):
        for m in self._imlogs.values():
            yield m


def arg_parse() -> argparse.Namespace:
    """
    コマンドライン引数を解析します。
    :return: コマンドライン引数(argparse.Namespace)
    """

    # コマンドライン引数の取得
    p = argparse.ArgumentParser()

    # 対象ログファイル
    p.add_argument(
        '--inputs',
        help='対象となるログファイル (ワイルドカードの利用可。)',
        required=True
    )

    # 圧縮ファイルかどうかのフラグ
    p.add_argument(
        '--compressed',
        dest='compressed',
        help='対象ファイルが圧縮ファイルかどうか.(Y or N)',
        choices=["Y", "N"],
        default="N"
    )

    # 出力先ディレクトリ
    p.add_argument(
        '--output',
        help='出力先のディレクトリの指定もしくはデータベースとのコネクション文字列を指定',
        required=True
    )

    # 西暦
    p.add_argument(
        '--year',
        help='記録された年を指定',
        type=int,
        metavar='Y'
    )

    #
    p.add_argument(
        '--yearfromctime',
        dest='yearfromctime',
        help='Use year from ctime.',
        action='store_true'
    )

    # 出力形式の指定
    p.add_argument(
        '--export-type',
        dest='type',
        help='出力ファイルのフォーマット(TSV,JSON,ORIG,ELS)',
        default='ORIG',
        choices=['TSV', 'JSON', 'ORIG', 'ELS']
    )

    args = p.parse_args()

    # 標準出力
    logging.info('=ArgParse===')
    logging.info(" Input files : {0}".format(args.inputs))
    logging.info(" Output      : {0}".format(args.output))
    logging.info(" Compressed  : {0}".format(args.compressed))
    logging.info(" Yaer        : {0}".format(args.year))
    logging.info(" Export Type : {0}".format(args.type))
    logging.info('=ArgParse===')

    return args


class MaillogWriter:
    __metaclass__ = ABCMeta
    _cols = ["analyzed", "start", "end", "host", "qid", "from", "org_to", "to",
             "msg_id", "nrcpt", "relay_host", "relay_ip", "relay_port",
             "dsn", "status", "size", "client_host", "client_ip", "proc",
             "delay", "delay_before", "delay_qmgr", "delay_con", "delay_trans", "dur"]

    def __init__(self):
        self._connection_string = ""

    @property
    def connection_string(self):
        return self._connection_string

    @connection_string.setter
    def connection_string(self, value):
        if isinstance(value, str):
            self._connection_string = value
        pass

    @abstractmethod
    def connect(self):
        print('Abstract')
        raise NotImplementedError()

    @abstractmethod
    def insert(self, m: dict):
        print('Abstract')
        raise NotImplementedError()

    @abstractmethod
    def disconnect(self):
        print('Abstract')
        raise NotImplementedError()


class MaillogTSVWriter(MaillogWriter):
    def __init__(self):
        super().__init__()
        self._delimiter = "\t"
        self._replace_char = ""
        self._line_header = ""
        self._line_footer = ""
        self._connection_string = ""
        self._fs = None
        self._header_flg = False
        return

    def connect(self):
        self._fs = open(self._connection_string, mode='w', buffering=WRITE_BUFFER)

    def insert(self, m: dict):
        if self._fs:
            if not self._header_flg:
                self._write_header()
                self._header_flg = True
            self._fs.write(self._dumps(m))
            self._fs.write("\n")
        else:
            raise IOError()

    def _header(self) -> str:
        return self._delimiter.join(super()._cols)

    def _write_header(self):
        self._fs.write(self._header())
        self._fs.write("\n")

    def _dumps(self, m: dict) -> str:
        """

        :rtype: str
        """
        tmp = []
        dlm = self._delimiter
        rep = self._replace_char
        try:
            tmp.append(str(m["parse_end"]))
            tmp.append(m["date_start_date"].isoformat())
            tmp.append(m["date_end_date"].isoformat())
            tmp.append(m["host"].replace(dlm, rep))
            tmp.append(m["queue_id"].replace(dlm, rep))
            tmp.append(m["envelope_from"].replace(dlm, rep))
            tmp.append(','.join(m["orig_to"]).replace(dlm, rep))
            tmp.append(','.join(m["envelope_to"]).replace(dlm, rep))
            tmp.append(m["message_id"].replace(dlm, rep))
            tmp.append(str(m["nrcpt"]))
            tmp.append(','.join(m["relay_host"]).replace(dlm, rep))
            tmp.append(','.join(m["relay_ip"]).replace(dlm, rep))
            tmp.append(','.join(m["relay_port"]).replace(dlm, rep))
            tmp.append(','.join(m["dsn"]).replace(dlm, rep))
            tmp.append(','.join(m["status"]).replace(dlm, rep))
            tmp.append(str(m["size"]))
            tmp.append(m["client_host"].replace(dlm, rep))
            tmp.append(m["client_ip"].replace(dlm, rep))
            tmp.append(','.join(m["proc"]).replace(dlm, rep))
            tmp.append(str(m["delay"]))
            tmp.append(str(m["delay_before_qmanager"]))
            tmp.append(str(m["delay_qmanager"]))
            tmp.append(str(m["delay_con_setup"]))
            tmp.append(str(m["delay_msg_trans"]))
            tmp.append(str(m["date_end_date"] - m["date_start_date"]))
            tmp.append(','.join(m["smtp_message"]).replace(dlm, rep))

        except TypeError as te:
            raise "TSVWriter.dumps Exception. {0}".format(te)

        return dlm.join(tmp)

    def disconnect(self):
        if self._fs:
            self._fs.close()
            self._fs = None


class MaillogJSONWriter(MaillogWriter):
    def __init__(self):
        super().__init__()
        self._fs = None
        return

    def connect(self):
        self._fs = open(self._connection_string, mode='w', buffering=WRITE_BUFFER)

    def _dumps(self, m: dict) -> str:
        """

        :rtype: str
        """

        return json.dumps(m, default=support_datetime_default)

    def insert(self, m: dict):
        self._fs.write(self._dumps(m))
        self._fs.write("\n")

    def disconnect(self):
        if self._fs:
            self._fs.close()
            self._fs = None


class MaillogElsWriter(MaillogWriter):
    def __init__(self):
        super().__init__()
        self._index = "postfix"
        self._type = "postfix_log"
        self._host = "127.0.0.1"
        self._port = "9200"
        self._es = None

    @property
    def connection_string(self):
        return self._connection_string

    @connection_string.setter
    def connection_string(self, value):
        """
        :param value:
         eg)
          "index=postfix type=postfix_log host=databasehost port=9200"
        :return:
        """
        if isinstance(value, str):
            for s in value.split():
                ary = s.split("=")
                if len(ary) == 2:
                    if ary[0] == "index":
                        self._index = ary[1]
                    elif ary[0] == "type":
                        self._type = ary[1]
                    elif ary[0] == "host":
                        self._host = ary[1]
                    elif ary[0] == "port":
                        self._port = ary[1]

    def connect(self):
        from elasticsearch import Elasticsearch
        self._es = Elasticsearch("{0}:{1}".format(self._host, self._port))

    def _dumps(self, m: dict) -> str:
        """

        :rtype: str
        """

        return json.dumps(m, default=support_datetime_default)

    def insert(self, m: dict):
        if self._es:
            self._es.index(index=self._index, doc_type=self._type, body=self._dumps(m))
        else:
            raise IOError()

    def disconnect(self):
        self._es = None


class MaillogOrgWriter(MaillogWriter):
    def __init__(self):
        super().__init__()
        self._fs = None
        self._delimiter = "\t"
        self._replace_char = ""
        return

    def connect(self):
        self._fs = open(self._connection_string, mode='w', buffering=WRITE_BUFFER)

    def _dumps(self, m: dict) -> str:
        """

        :rtype: str
        """
        fmt = "anlyzd={0}\tstart={1}\tend={2}\thost={3}\tqid={4}\tfrom={5}\torg_to={6}\tto={7}\t" \
              "msgid={8}\tnrcpt={9}\trlyhost={10}\trlyip={11}\trlyprt={12}\tdsn={13}\t" \
              "status={14}\tsize={15}\tclhost={16}\tclip={17}\tporc={18}\tdelay={19}\t" \
              "dlybfr={20}\tdlyqmgr={21}\tdlycon={22}\tdlytrns={23}\tdur={24}\tmsg={25}"
        try:
            dlm = self._delimiter
            rep = self._replace_char
            buf = fmt.format(
                str(m["parse_end"]),
                m["date_start_date"].isoformat(),
                m["date_end_date"].isoformat(),
                m["host"].replace(dlm, rep),
                m["queue_id"].replace(dlm, rep),
                m["envelope_from"].replace(dlm, rep),
                ','.join(m["orig_to"]).replace(dlm, rep),
                ','.join(m["envelope_to"]).replace(dlm, rep),
                m["message_id"].replace(dlm, rep),
                str(m["nrcpt"]),
                ','.join(m["relay_host"]).replace(dlm, rep),
                ','.join(m["relay_ip"]).replace(dlm, rep),
                ','.join(m["relay_port"]).replace(dlm, rep),
                ','.join(m["dsn"]).replace(dlm, rep),
                ','.join(m["status"]).replace(dlm, rep),
                str(m["size"]),
                m["client_host"].replace(dlm, rep),
                m["client_ip"].replace(dlm, rep),
                ','.join(m["proc"]).replace(dlm, rep),
                str(m["delay"]),
                str(m["delay_before_qmanager"]),
                str(m["delay_qmanager"]),
                str(m["delay_con_setup"]),
                str(m["delay_msg_trans"]),
                str(m["date_end_date"] - m["date_start_date"]),
                ','.join(m["smtp_message"]).replace(dlm, rep)
            )

        except TypeError as te:
            raise "MaillogOrgWriter.dumps Exception. {0}".format(te)

        return buf

    def insert(self, m: dict):
        self._fs.write(self._dumps(m))
        self._fs.write("\n")

    def disconnect(self):
        if self._fs:
            self._fs.close()
            self._fs = None


def create_writer(txt: str, input_fn: str, output: str):
    """
    出力オブジェクトの生成
    :param input_fn:
    :param txt: JSON / TSV / ORIG
    :return: MaillogWriterを継承したオブジェクト
    """
    basename, ext = os.path.splitext(os.path.basename(input_fn))
    output_fn = "{0}/{1}{2}.txt".format(output, basename, ext)

    if txt == 'JSON':
        mtw = MaillogJSONWriter()
        mtw.connection_string = output_fn
        return mtw

    elif txt == 'TSV':
        mtw = MaillogTSVWriter()
        mtw.connection_string = output_fn
        return mtw

    elif txt == 'ELS':
        mtw = MaillogElsWriter()
        mtw.connection_string = output
        return mtw

    else:
        mtw = MaillogOrgWriter()
        mtw.connection_string = output_fn
        return mtw


def main():
    """
    メインループ
    :return: void
    """
    stime = datetime.datetime.now()

    # LogFormatの指定
    logging.basicConfig(
        format='%(asctime)s : %(levelname)s:%(message)s',
        level=LOGGING_LEVEL
    )

    # コマンドライン引数の取得
    args = arg_parse()

    # ファイル名の指定
    inputs = glob.glob(args.inputs)
    for input_fn in inputs:

        # パーサーオブジェクトの指定
        logging.info(" Analyzing [{0}]".format(input_fn))
        mp = MaillogParser(input_fn)

        # 圧縮状態の指定
        if args.compressed == 'Y':
            mp.compressed = True
        else:
            mp.compressed = False

        # 年号の設定
        if args.year is not None:
            # 引数で明示的に年賀指定された場合
            mp.year = args.year
        elif args.yearfromctime:
            # 引数でctimeが指定された場合。
            # WindowsとLinuxでctimeの意味するところが異なるので注意
            dt = datetime.datetime.fromtimestamp(os.stat(input_fn).st_ctime)
            mp.year = dt.year

        # ログのパース実行
        try:
            # 標準出力
            ps = datetime.datetime.now()
            logging.info("Start analysis.")

            # Writerの作成
            mtw = create_writer(args.type, input_fn, args.output)
            mtw.connect()

            # 解析が終わったログを書き込み
            for imlog in mp.parse():
                logging.debug(imlog)
                mtw.insert(imlog)

            # 解析が終わっていないログを書き込み
            for imlog in mp.get_noncomplete_maillog():
                mtw.insert(imlog)

            # 標準出力
            pe = datetime.datetime.now()
            cnt = mp.parsed_count
            logging.info("End analysis. The number of rows is {0}.".format(cnt))
            logging.info("The processing take {0}".format((pe - ps)))

        except UnicodeDecodeError as ude:
            # テキスト形式を想定してファイルを開いたが、エンコードエラーが発生した場合
            logging.error("ファイルを開いた際にデコードエラーが発生しました。{0}".format(ude))

        except ValueError as ve:
            # 日付が間違っている場合は処理を続行しない
            logging.error("日時に誤りがあります。当該ログの処理を中断します。{0}".format(ve))

        finally:
            mtw.disconnect()

    # 標準出力
    etime = datetime.datetime.now()
    logging.info('=Parse end.=== {0}'.format(etime - stime))


def support_datetime_default(obj) -> str:
    """
    json.dumpsでdatetimeオブジェクトを扱うためのコールバック
    :param obj: datetime.datetime
    :return: datetime.datetimeをiso不フォーマットに変更した文字列
    """
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError(repr(obj) + " is not JSON serializable")


if __name__ == '__main__':

    if PROFILE_FLAG:
        import cProfile

        cp = cProfile.Profile()
        cp.enable()
        main()
        cp.disable()
        # cp.print_stats()
        cp.dump_stats('plp.stats')
    else:
        main()
