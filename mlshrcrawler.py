#!/usr/bin/env python3
__author__ = 'yalu'

import os
import requests
import json
import sqlite3
import sys
import getopt
from threading import Thread
from time import time, mktime, strptime, asctime, gmtime, strftime, sleep
from pedetails.pedetailer import PEDetailer
from logger import Logger
import magic

# import urllib3
# urllib3.disable_warnings()

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
except (AttributeError, ImportError):
    pass

malshare_types = "HTML", "PE32", "Zip"
malshare_api_keys = list()
current_malshare_api_key_index = -1
virus_total_api_keys = list()
virustotal_api_key = None
current_virus_total_api_key_index = -1
DB_ADRESS = "malshare.db"
PE_DB = "pedb"
FIRST_DATE_IN_MALSHARE = "2013 04 06"
VIRUS_TOTAL_FILE_SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VIRUS_TOTAL_REPORT_REQUEST_URL = "http://virustotal.com/vtapi/v2/file/report"
MD5_FOR_TESTS = "00c22bba2c767f5bdc5ea9eaa139e221"
# example of daily string: http://malshare.com/daily/year-month-day/malshare_fileList.year-month-day.txt
url_daily_string_head = "http://malshare.com/daily/"
url_string_head = "http://malshare.com/"
my_logger = Logger()
url_with_api_string_head = url_string_head + "api.php?api_key="
str_action = "&action="
str_action_get_list_html = str_action + "getlist"
str_action_get_list_raw = str_action + "getlistraw"
str_action_get_list_sources_html = str_action + "getsources"
str_action_get_list_sources_raw = str_action + "getsourcesraw"
str_action_downloadfile = str_action + "getfile&hash="
str_action_details = str_action + "details&hash="
str_action_last24h_md5list_from_file_type = str_action + "type&type="


def main(argv):
    """
    This method will handle the input parameters and args and validate each of them.
    Then will pass control to the method real_extraction which do the hard work.
    :param argv:
    :return:
    """
    global virus_total_api_keys
    global current_virus_total_api_key_index
    global virustotal_api_key
    global malshare_api_keys
    global current_malshare_api_key_index

    usage = "mlshrcrawler -s/--starting-date Starting date(%Y %m %d) -e/--ending-date Ending date (%Y %m %d) \n" \
            "             -o/--output-database Output database address -p/--download-to-address Address in the pc  \n" \
            "              where to download files -t/--file-type Filter for type of file -h/--help \n" \
            "              -d/--download This option will enable the download. \n" \
            "              -r/--register This option will enable the register into db -k/--api-key Malshare api key, \n" \
            "              -q/--apikey-from-file Address of a file containing one or many Malshare API Keys separated with line jumps \n" \
            "              -c/--continue-downloading If specified will look for the last element in the db specified \n" \
            "              and will continue downloading from the rest elements in that date. -n/--notify-each A number \n" \
            "              of instances after which the program will notify the status of downloaded and or registered. \n " \
            "              -v/--last-24h-virus-scan Iniside an infinite loop will download last 24 hours found viruses \n " \
            "              on malshare dataset, send it to virustotal and register the virus metadata and  results of \n" \
            "              the scan. -w/--virustotal-apikey Virus total api key, -a/--virustotal-apikey-fromfile Load \n" \
            "              one or many virus total api keys from specified file address, each api key in the file separated by line jumps. \n" \
            "              -f/--verbose-to-file Print results of any operation to file" \

    try:
        opts, args = getopt.getopt(argv, "hs:e:o:p:t:k:q:n:drcvw:a:f:", ["help", "starting-date=", "ending-date=",
                                                               "output-database=", "download-to-address=",
                                                                 "file-type=", "download", "register",
                                                                 "api-key=", "apikey-from-file=",
                                                               "continue-downloading", "notify-each=",
                                                               "last-24h-virus-scan", "virustotal-apikey=",
                                                               "virustotal-apikey-fromfile=,verbose-to-file="])
        # print("Args is : " + str(args))
        # print("Opts is : " + str(opts))
        # print("Args is : " + str(args))

    except getopt.GetoptError as e:
        print("GetOpt Error:" + e.msg)
        print("Usage is: " + usage)
        sys.exit(2)

    _starting_date = None
    _ending_date = None
    _output_database_address = None
    _output_database_handler = None
    _hashes_list = []
    _pc_address_to_download = "."
    _type_of_file = None
    _download_enabled = None
    _register_enabled = None
    _continue_downloading = False
    _malshare_api_key = None
    _virus_total_api_key = None
    _notify_after = None
    _loop24h_virus_scan = False
    _verbose_to_file = None
    recent_virus_analysis_continue_from_existent_data = False
    if len(opts) == 0:
        print(usage)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Usage is: " + usage)
            sys.exit(1)
        elif opt in ("-s", "--starting-date"):
            _date = arg
            if not is_date_valid(_date):
                print("Sorry, seems like date is not valid. Must be in the format %Y %m %d, e.i 2014 04 01")
                sys.exit(2)
            _starting_date = _date
            first_date_in_malshare = mktime(strptime(FIRST_DATE_IN_MALSHARE, "%Y %m %d"))
            if mktime(strptime(_starting_date, "%Y %m %d")) < first_date_in_malshare:
                print("The date entered is before the first date in malshare, setting to the first date in malshare: " + FIRST_DATE_IN_MALSHARE)
                _starting_date = FIRST_DATE_IN_MALSHARE
        elif opt in ("-e", "--ending-date"):
            #print("Specified ending date, args is: " + str(args))
            _date = arg
            if not is_date_valid(arg):
                print("Sorry, seems like date is not valid. Must be in the format %Y %m %d, e.i 2014 04 01")
                sys.exit(2)
            _ending_date = _date
            _now = time()
            if mktime(strptime(_ending_date, "%Y %m %d")) > _now:
                print("The date entered is after today, setting to today: " + strftime(_now))
        elif opt in ("-o", "--output-database"):
            if os.path.exists(arg):
                recent_virus_analysis_continue_from_existent_data = True
            con = connect_to_database(arg)
            _output_database_handler = con
            _output_database_address = arg
            _register_enabled = True
        elif opt in ("-p", "--download-to-address"):
            try:
                os.makedirs(arg)
            except Exception as e:
                pass
            _pc_address_to_download = arg
            _download_enabled = True
        elif opt in ("-t", "--file-type"):
            if _type_of_file not in malshare_types:
                print("The specified file type is wrong")
                correct_file_types = ""
                for file_type in malshare_types:
                    correct_file_types += " " + file_type
                print("Correct file types are: " + correct_file_types)
                sys.exit(2)
            _type_of_file = arg
        elif opt in ("-d", "--download"):
            print("Setting download enabled")
            _download_enabled = True
        elif opt in ("-r", "--register"):
            _register_enabled = True
        elif opt in ("-q", "--apikey-from-file"):
            #print("Api key from file")
            try:
                with open(arg) as _f:
                    _malshare_api_key = _f.read()
                #print("Api key found is: " + _api_key)

                _keys = _malshare_api_key.split("\n")
                # while "\n" in _malshare_api_key:
                #     _malshare_api_key = _malshare_api_key[:len(_malshare_api_key) - 1]
                for _api_key in _keys:
                    if _api_key.strip() == "":
                        continue
                    print("ValidatingApiKey: " + _api_key)
                    _valid_api_key = is_apikey_valid(_api_key)
                    if _valid_api_key == 1:
                        malshare_api_keys.append(_api_key)
                    if _valid_api_key == 0:
                        print("Couldn't determinate if the provided api key is valid")
                        sys.exit(2)
                    elif _valid_api_key == -1:
                        print("Definitely the api key provided is not valid.")
                        sys.exit(2)

                current_malshare_api_key_index = 0
            except FileNotFoundError:
                print("Seems like the file with the api key provided don't exist in that address.")
                sys.exit(2)
        elif opt in ("-k", "--api-key"):
            _valid_api_key = is_apikey_valid(arg)
            if _valid_api_key == 1:
                # _malshare_api_key = arg
                malshare_api_keys.append(arg)
                current_malshare_api_key_index = 0
            elif _valid_api_key == 0:
                print("Couldn't determinate if the provided api key is valid")
                sys.exit(2)
            elif _valid_api_key == -1:
                print("Definitely the api key provided is not valid.")
                sys.exit(2)
        elif opt in ("-c", "--continue-downloading"):
            _continue_downloading = True
        elif opt in ('-n', "--notify-each"):
            try:
                _notify_after = int(arg)
            except ValueError:
                print("The notify after argument is wrong, must be a number.")
                sys.exit(2)
        elif opt in ('-v', '--last-24h-virus-scan'):
            _loop24h_virus_scan = True
        elif opt in ('-w', '--virustotal-apikey'):
            _valid_api_key,_ = is_virustotal_apikey_valid(arg)

            if _valid_api_key == 1:
                virus_total_api_keys.append(arg)
            elif _valid_api_key == 0:
                print("Couldn't determinate if the provided api key is valid")
                sys.exit(2)
            elif _valid_api_key == -1:
                print("Definitely the api key provided is not valid.")
                sys.exit(2)
            current_virus_total_api_key_index = 0
            virustotal_api_key = virus_total_api_keys[current_virus_total_api_key_index]
        elif opt in ('-f', '--verbose-to-file'):
            global my_logger
            my_logger = Logger(arg)
        elif opt in ('-a', '--virustotal-apikey-fromfile'):

            try:
                with open(arg) as _f:
                    _read_keys = _f.read()

                for _key in _read_keys.split('\n'):
                    if _key.strip() == "":
                        continue
                    _valid_api_key,_ = is_virustotal_apikey_valid(_key)
                    if _valid_api_key == 1:
                        virus_total_api_keys.append(_key)
                    if _valid_api_key == 0:
                        print("Couldn't determinate if the provided api key is valid")
                        sys.exit(2)
                    elif _valid_api_key == -1:
                        print("Definitely the api key provided is not valid.")
                        sys.exit(2)
                current_virus_total_api_key_index = 0
                virustotal_api_key = virus_total_api_keys[current_virus_total_api_key_index]
            except Exception as vte:
                print("Error Validating VirusTotal Keys is: " + str(vte.args))
                print("Seems like the file with the api key provided don't exist in that address or the keys are not"
                      " well writen into the file.")
                sys.exit(2)
        else:
            print(usage)
            sys.exit(2)
    if current_malshare_api_key_index < 0:
        print("You must specify an API key for this program to work.")
        sys.exit(2)
    if _loop24h_virus_scan:
        if current_virus_total_api_key_index < 0:
            print("Must specify VirusTotal api key.")
            print(usage)
            sys.exit(2)
        if current_malshare_api_key_index < 0:
            print("Must specify Malshare api key.")
            print(usage)
            sys.exit(2)
        if _pc_address_to_download is None:
            print("Must specify pc address to download files.")
            print(usage)
            sys.exit(2)
        if _output_database_address is None:
            print("Must specify a database address.")
            print(usage)
            sys.exit(2)
        virustotal_analysis(_pc_address_to_download, _output_database_handler,
                            _output_database_address, recent_virus_analysis_continue_from_existent_data)
    else:
        real_extraction(_malshare_api_key, _starting_date, _ending_date, _output_database_address,
                        _pc_address_to_download, _type_of_file, _download_enabled, _register_enabled,
                        _continue_downloading, _notify_after)

class Malshare_tuple():
    """
    Class for the instances of tuples to Malshare database.

    """

    def __init__(self, tuple_id=-1, md5="", sha1="", sha256="", ssdeep="", file_type="", sources=list(), date_posted="",
                 date_downloaded="", pc_address_download="", magic_file_type=""):
        """

        :param tuple_id: Malware tuple id inside the local Malshare database
        :param md5: Md5 summary
        :param sha1: Sha1 summary
        :param sha256: Sha256 summary
        :param ssdeep: Ssdeep summary
        :param file_type: File type, commonly found PE32, HTML, Zip
        :param sources: List of sources where was found the malware.
        :param date_posted: Date in which was posted to Malshare.
        :param date_downloaded: Last date in which was downloaded by this user.
        :param pc_address_download: Path on PC where the file was downloaded.
        :param magic_file_type: File type as obtained from magic module.
        :type tuple_id: int
        :type md5: str
        :type sha1: str
        :type sha256: str
        :type ssdeep: str
        :type file_type: str
        :type sources: list
        :type date_posted: str
        :type date_downloaded: str
        :type pc_address_download: str
        :type magic_file_type: str
        :return: Malshare_tuple
        """
        self.tuple_id, self.md5, self.sha1, self.sha256, self.ssdeep, self.file_type, self.sources, self.date_posted, \
        self.date_downloaded, self.pc_address_download, self.magic_file_type = tuple_id, md5, sha1, sha256, ssdeep, file_type, sources, \
                                                         date_posted, date_downloaded, pc_address_download, magic_file_type

    def add_source(self, source):
        """
        Add source to sources list
        :param source: String of the source, usually a url string
        :type source: str
        :return:
        """
        self.sources.append(source)


def get_daily_url_from_date(year, month, day):
    """
    Returns a url string to be used to get the hash of the files uploaded on the specified date
    by the params.
    :param year
    :param month
    :param day
    :type day: int
    :type month: int
    :type year: int
    :return str
    """
    _today = gmtime(time())

    if len(str(day)) == 1: day = "0" + str(day)
    if len(str(month)) == 1: month = "0" + str(month)
    aux = str(year) + "-" + str(month) + "-" + str(day)
    if _today.tm_year == int(year) and _today.tm_mon == int(month) and _today.tm_mday == int(day):
        return url_daily_string_head + "malshare.current.txt"
    return url_daily_string_head + aux + "/malshare_fileList." + aux + ".txt"


def get_hashlist_from_date(year, month, day):
    """
    Returns a list with the hash of the files uploaded in the data specified
    by the parameters
    :param year
    :param month
    :param day
    :type day: int
    :type month: int
    :type year: int
    :return list
    """

    url = get_daily_url_from_date(year, month, day)
    r = requests.get(url)
    b = r.content
    s = b.decode('utf-8')
    return s.split('\n')


def get_last24hlist_html(api_key):
    """
    List MD5 hashes from the past 24 hours (HTML formatted)
    :param api_key
    :type api_key: str
    :return requests.models.Response
    """
    url = url_with_api_string_head + api_key + str_action_get_list_html
    return requests.get(url)


def get_last24hlist_raw(api_key):
    """
    List MD5 hashes from the past 24 hours (raw formatted)
    :param api_key
    :type api_key: str
    :return requests.models.Response
    """
    url = url_with_api_string_head + api_key + str_action_get_list_raw
    return requests.get(url)


def get_last24hsourceslist_html(api_key):
    """
    List file sources from the past 24 hours (HTML formatted)
    :param api_key
    :type api_key: str
    :return requests.models.Response
    """
    url = url_with_api_string_head + api_key + str_action_get_list_sources_html
    return requests.get(url)


def get_last24hsourceslist_raw(api_key):
    """
    List file sources from the past 24 hours (raw formatted)
    :param api_key
    :type api_key: str
    :return requests.models.Response
    """
    url = url_with_api_string_head + api_key + str_action_get_list_sources_raw
    return requests.get(url)


def download_file(_file_hash, destination):
    """
    Download the file specified by hash to the destination specified
    :param api_key:
    :param _file_hash:
    :param destination:
    :return: bool, str
    """
    api_key = malshare_api_keys[current_malshare_api_key_index]
    TAG = "DownloadingFileFromMalshare"
    my_logger.log(TAG, "Downloading hash: " + _file_hash)
    if os.path.exists(destination):
        my_logger.log(TAG, "File exists no need to download")
        return True, "File exists no need to download"
    _url = "http://malshare.com/api.php?api_key=" + api_key + "&action=getfile&hash=" + _file_hash
    r = requests.get(_url)
    content = r.content
    _response = ""
    try:
        _response = content.decode('utf-8')
    except Exception:
        pass
    if 'ERROR! => Over Request Limit.' in _response:
        my_logger.log(TAG, _response)
        set_new_malshare_api_key_index()
        return download_file(_file_hash, destination)
    if 'not activated' in _response:
        my_logger.log(TAG, _response)
        return False, "Wrong api key"
    if 'Invalid Hash' in _response:
        my_logger.log(TAG, _response)
        return False, "Hash found as invalid"
    if not r.ok:
        my_logger.log(TAG, "Url response code not 200")
        return False, "Url response code not 200"
    try:
        with open(destination, 'wb') as f:
            f.write(content)
        my_logger.log(TAG, "File with hash: " + _file_hash + " downloaded to: " + destination)
        return True, "File with hash: " + _file_hash + " downloaded to: " + destination
    except Exception as e:
        return False, str(e.args)


def handle_hash(file_hash, destination_folder=".", _db_handler=None,
                _register_enabled=True, _download_enabled=False, _processing_date="", _file_type=None, _pedb=None):
    """
    Download and/or register a specified hash, by default it only download to the specified address.
    Returns a tuple with a dict and a array, the first with the success or failure on download and register process
    expressed with bool values for download in the first position and for register in the second. The array contains
    the messages logged on each step.
    :param file_hash: Hash of the malware to be handled
    :param destination_folder: Address where the file will be downloaded
    :param _db_handler: A handler to the db to be used
    :param _register_enabled: If true will register to a db. Default value is True
    :param _download_enabled: If true will download to the specified address. Default value is False
    :param _file_type: Will handle hash if belong of a file with the type specified by this parameter
    :type _db_handler: sqlite3.Connection
    :return: dict(), []
    """
    api_key = malshare_api_keys[current_malshare_api_key_index]
    TAG = "Handling hash " + file_hash
    my_logger.log(TAG, "")
    _result_messages = []
    _download_to = ""
    _download_correct = False
    _register_correct = False
    _download_date_to_db = None
    magic_file_type = ""
    details = get_file_details_json(file_hash, api_key)
    if _file_type is not None:
        # print(TAG + "File type specified is: " + _file_type)
        if not _file_type == details["F_TYPE"]:
            # print(TAG + "This hash file type is not desired to be processed, so jumping")
            return ({"download_ok": True, "register_ok": True}, ["Unwanted file type"])
    if _download_enabled:
        my_logger.log(TAG, "Download enabled, trying to download file")
        # print(TAG + "Download enabled, trying to download file")
        if not os.path.exists(destination_folder):
            my_logger.log(TAG, "Destination folder dont exist so not downloading this instance. Destination is: " + destination_folder)
            # print(TAG + "Destination address dont exist so not downloading this instance.")
            _download_correct = False
            _result_messages.append("Specified path don't exist.")
        else:
            _download_to = os.path.join(os.path.abspath(destination_folder), file_hash)
            _download_result = download_file(file_hash, _download_to)
            _download_correct = _download_result[0]
            _result_messages .append(_download_result[1])
            if _download_correct:
                magic_file_type = magic.from_file(_download_to)
                magic_file_type = magic_file_type.decode('utf-8')
                # print(TAG + "File downloaded successfully.")
                _download_date = gmtime(time())
                _download_date_to_db = asctime(_download_date)
                if _pedb is not None:
                    try:
                        pedetailer = PEDetailer(_pedb, my_logger, _db_handler)
                        _pedetailsuccess, _pedetailmsg = pedetailer.analyse_pe_file(os.path.join(destination_folder,
                                                                                                 file_hash), file_hash)
                        if _pedetailsuccess:
                            my_logger.log(TAG, "Registered PE file details successfully: " + _pedetailmsg)
                        else:
                            my_logger.log(TAG, "Error registering PE file, was: " + _pedetailmsg)
                    except Exception as peerror:
                        my_logger.log(TAG, "Error registering PE file, was: " + str(peerror.args))

    if _register_enabled:
        # print(TAG + "Register is enabled, putting all on db")
        if _db_handler is None:
            # print(TAG + "Not specified db handler, will not register this instance")
            _register_correct = False
            _result_messages.append(" Not specified db handler")
        else:
            try:
                t = Malshare_tuple(-1, details.get('MD5'), details.get('SHA1'), details.get('SHA256'), details.get("SSDEEP"),
                                   details.get("F_TYPE"), details.get('SOURCES'), _processing_date, _download_date_to_db,
                                   _download_to, magic_file_type)
                _inserting_result = insert_tuple(_db_handler, t)
                _register_correct = _inserting_result[0]
                _result_messages.append(_inserting_result[1])
                # print(TAG + "Inserting tuple says: " + str(_inserting_result))
            except Exception as e:
                # print(TAG + "Something went wrong registering: " + str(e.args))
                _register_correct = False
                _result_messages.append("Error inserting tuple in db: " + str(e.args))
    _partial_results = {'download_ok': True, 'register_ok': True}
    if _download_enabled and not _download_correct:
        _partial_results['download_ok'] = False
    if _register_enabled and not _register_correct:
        _partial_results['register_ok'] = False
    return _partial_results, _result_messages

def get_file_details_json(file_hash, api_key):
    """
    Get file details (JSON formatted)
    :param file_hash
    :param api_key
    :type file_hash: str
    :type api_key: str
    :return dict
    """
    TAG = "GettingFileDetailsJSon"
    my_logger.log(TAG, "File hash is: " + file_hash + " ApiKeyis: " + api_key)
    default_json = '{"MD5": "' + file_hash + '" , "SSDEEP": "No information found on malshare.", ' \
                   '"SOURCES":[] , "SHA256": "No information found on malshare.", '\
                   '"SHA1": "No information found on malshare.", "F_TYPE": "No information found on malshare."}'
    url = url_with_api_string_head + api_key + str_action_details + file_hash
    r = requests.get(url)
    request_content = r.content.decode('utf-8')
    #print("Obtaining details of hash " + file_hash + " : " + request_content)
    #print("Json will decode: " + request_content)
    try:
        my_logger.log(TAG, "Found details json.")
        return json.loads(request_content)
    except Exception:
        my_logger.log(TAG, "Not Found Details Json, Returning Default")
        return json.loads(default_json)


def get_filehashlast24h_fromfiletype_json(file_type, api_key):
    """
    Get file details (JSON formatted)
    :param file_type
    :param api_key
    :type file_type: str
    :type api_key: str
    :return list
    """

    url = url_with_api_string_head + api_key + str_action_last24h_md5list_from_file_type + file_type
    r = requests.get(url)
    return json.loads(r.content.decode('utf-8'))


def connect_to_database(here):
    """
    Connect to a database if exists else create it.
    Returns the connection handler.
    :param here: String of the place where the database will be created
    :type here: str
    :return: sqlite3.Connection
    """
    con = sqlite3.connect(here)
    curs = con.cursor()
    try:
        curs.execute("SELECT mid FROM malware LIMIT 1")
        return con
    except sqlite3.OperationalError:
        pass
    script = [
        "CREATE TABLE IF NOT EXISTS malware (mid INTEGER NOT NULL, md5 VARCHAR , SHA1 VARCHAR , SHA256 VARCHAR , SSDEEP VARCHAR , FILE_TYPE VARCHAR, DATE_POSTED VARCHAR, PRIMARY KEY(mid))",
        "CREATE TABLE IF NOT EXISTS source(md5 VARCHAR , source VARCHAR );",
        "CREATE TABLE IF NOT EXISTS download(md5 VARCHAR , download_date VARCHAR , pc_address_download VARCHAR, magic_file_type VARCHAR )",
        "CREATE TABLE IF NOT EXISTS vtscan(scanid VARCHAR, md5 VARCHAR, _date VARCHAR, positives INTEGER, total INTEGER, permalink VARCHAR)",
        "CREATE TABLE IF NOT EXISTS scandetail(scanid VARCHAR, antivirus VARCHAR , detected INTEGER, version VARCHAR, result VARCHAR, last_date VARCHAR )",
        "CREATE TABLE IF NOT EXISTS pefile(provided_md5 VARCHAR ,md5 VARCHAR, sha1 VARCHAR , sha256 VARCHAR , sha512 VARCHAR , imp_hash VARCHAR , compilation_date VARCHAR , suspicious INTEGER)",
        " CREATE TABLE IF NOT EXISTS pesection(provided_md5 VARCHAR ,nome VARCHAR , tamanho VARCHAR , md5 VARCHAR )",
        "CREATE TABLE IF NOT EXISTS peimport(provided_md5 VARCHAR ,md5 VARCHAR , address VARCHAR , nome VARCHAR , dll VARCHAR )",
        "CREATE TABLE IF NOT EXISTS peexport(provided_md5 VARCHAR ,md5 VARCHAR , address VARCHAR , nome VARCHAR , ordinal VARCHAR )",
        "CREATE TABLE IF NOT EXISTS vtqueuedscan(md5 VARCHAR, file_address VARCHAR, data_postagem VARCHAR, scan_id VARCHAR, response_code INTEGER, permalink VARCHAR, verbose_msg VARCHAR )"
    ]
    for stmnt in script:
        curs.execute(stmnt)
        con.commit()
    return con

def vt_get_report_until_ready(api_key, resource, db_address):
    """
    Makes requests to obtain the report identified by the parameter resource, until a result is ready.
    Then the results are inserted on a database located on the specified db_address.
    This should run on a separate thread.
    :param api_key:
    :param resource:
    :return:
    """
    TAG = "GettingReportUntilReady"
    running = True
    my_logger.log(TAG, "Executing in new thread, get report of sent file: " + resource)
    while running:
        try:
            code, _json = vt_get_report(api_key, resource)
            if code == 1:
                my_logger.log(TAG, "Got report with code 1")
                insert_scan(db_address, _json)
                running = False
            sleep(5)
        except Exception as e:
            my_logger.log(TAG, "ERROR obtaining report: " + str(e.args))
            sleep(5)


def insert_scan(con, details):
    """
    Insert details of a virustotal scan on db
    :param con:
    :param details: 
    :return:
    """
    TAG = "InsertinScanResults"
    my_logger.log(TAG, "Inserting scan details for scanid: " + str(details['scan_id']))
    try:
        #con = sqlite3.connect(db_address)
        cursor = con.cursor()
        #Inserting scan metadata and scan details on db
        cursor.execute("INSERT INTO vtscan(scanid, md5, _date, positives, total, permalink) VALUES (?,?,?,?,?,?)",
        [details['scan_id'], details['md5'], details['scan_date'], details['positives'], details['total'],
         details['permalink']])
        for _item in details['scans'].items():
            antivirus = _item[0]
            result = _item[1]
            cursor.execute("INSERT INTO scandetail(scanid, antivirus, detected, version, result, last_date) VALUES "
                           "(?,?,?,?,?,?)", [details['scan_id'], antivirus, str(result['detected']), result['version'],
                                                   str(result['result']), result['update']])
        con.commit()
        my_logger.log(TAG, "Scan Inserted succesfully")
        return True, "Scan Inserted succesfully"
    except Exception as e:
        my_logger.log(TAG, "Error inserting scan: " + str(e.args))
        return False, "ERROR inserting scan detail: " + str(e.args)
    
def vt_get_report(api_key, resource):
    """
    Will request the virustotal API to retrieve existent reports on the file.
    This method returns a tuple with the first element being a flag with one of the following values and its meanings:
      0 : The file have not been scanned before
      1 : The file have already been scanned
      -2 : The file is queued for analysis
      -1: Couldn't determinate, some error was raised.
     The second element of the tuple is a json with details of this process, may include the report or if an error
     was raised details of the error.
    :param api_key:
    :param resource:
    :return:
    """
    TAG = "GettingFileScanReport"
    my_logger.log(TAG, "Getting report for resource: " + resource)
    try:
        _request_url = VIRUS_TOTAL_REPORT_REQUEST_URL
        _params = {'apikey': api_key, 'resource': resource, 'allinfo': 1}
        _response = requests.get(_request_url, params=_params)
        if not _response.ok:
            return -1, json.loads('{"error": "Network error couldnt connect with the URL"}')
        _content = _response.content.decode('utf-8')
        #print("GettingReport, Response is: " + str(_content))
        j = json.loads(_content)
        return j['response_code'], j
    except Exception as e:
        my_logger.log(TAG, "ERROR: " + str(e.args))
        my_logger.log(TAG, "Response is: " + str(_response.content))
        my_logger.log(TAG, "Response is: " + str(_content))
        return -1, json.loads('{"error":"' + str(e.args) + '"}')


def vt_file_scan(api_key, file_address, db_handler):
    """
    This method sends a request to the virustotal API to analyse a file which location is specified in file_address.
    Returns True if the file was succesfully queued for analysis and the data of the process in the second parameter
    Returns False if an error was raised and the error details.
    :param api_key:
    :param file_address:
    :return:
    """
    TAG = "SendingFileToScan"
    my_logger.log(TAG, "Will send file for scan, file in address: " + file_address)

    try:
        file_address = os.path.abspath(file_address)
        my_logger.log(TAG, "File address is: " + file_address)
        _file_name = os.path.basename(file_address)
        my_logger.log(TAG, "File name is: " + _file_name)
        _params = {'apikey': api_key}
        _files = {'file': (_file_name, open(file_address, 'rb').read())}
        _response = requests.post(VIRUS_TOTAL_FILE_SCAN_URL, params=_params, files=_files, verify=False)
        if _response.ok:
            _data_postagem = asctime(gmtime(time()))
            _content = _response.content.decode('utf-8')
            my_logger.log(TAG, "ScanningFile" + file_address + " : " + _content)

            try:
                my_logger.log(TAG, "Inserting on db this file sent to scan details.")
                _db_cursor = db_handler.cursor()
                _j = json.loads(_content)
                _sql = "INSERT INTO vtqueuedscan(md5 ,file_address ,data_postagem ,scan_id ,response_code, permalink, " \
                       "verbose_msg) VALUES (?, ?, ?, ?, ?, ?, ?) "
                _db_cursor.execute(_sql, [_j['md5'], file_address, _data_postagem, _j['scan_id'], _j['response_code'],
                                          _j['permalink'], _j['verbose_msg']])
                db_handler.commit()
                my_logger.log(TAG, "Succesfully inserted sent to scan details.")
            except Exception as je:
                my_logger.log(TAG, "Error inserting scan details: " + str(je.args))



            #return True, json.loads(_content)
        else:
            my_logger.log(TAG,"ScanningFile: " + file_address + "  Network Error")
            #return False, "ERROR: Network connection error."
    except Exception as e:
        _error = "ERROR: " + str(e.args)
        my_logger.log(TAG, "ScanningFile: " + file_address + " Error: " + _error)
        #return False, _error


def set_new_malshare_api_key_index():
    global current_malshare_api_key_index
    if current_malshare_api_key_index == len(malshare_api_keys) - 1:
        current_malshare_api_key_index = 0
    else:
        current_malshare_api_key_index = current_malshare_api_key_index + 1


def set_new_virustotal_api_key_index():
    global current_virus_total_api_key_index
    global virus_total_api_keys
    global virustotal_api_key

    if current_virus_total_api_key_index == len(virus_total_api_keys) - 1:
        current_virus_total_api_key_index = 0
    else:
        current_virus_total_api_key_index = current_virus_total_api_key_index + 1

    virustotal_api_key = virus_total_api_keys[current_virus_total_api_key_index]


def get_list_of_inserted_hashes(db_handler):
    _sql = "SELECT md5 FROM malware"
    _cursor = db_handler.cursor()
    all = _cursor.execute(_sql).fetchall()
    return [x[0] for x in all]


def get_list_of_hashes_which_analysis_was_already_obtained(db_handler):
    _sql = "SELECT md5 FROM vtscan"
    _cursor = db_handler.cursor()
    all = _cursor.execute(_sql).fetchall()
    return [x[0] for x in all]


def virustotal_analysis(malshare_output_folder, output_db_handler, db_file_address, continue_from_existent_data = False):
    """
    This method will retrieve the last files posted on malshare and send those previously not handled
    to virustotal for analysis. The analysis results will be dumped to virustotal_analysis_output_folder, the downloaded
    virus samples will be dumped to malshare_output_folder and malshare files details will be registered on output_db.
    :param malshare_api_key:
    :param address_file:
    :param output_db_handler:
    :param virustotal_analysis_output_folder:
    :return:
    """
    global virustotal_api_key
    malshare_api_key = malshare_api_keys[current_malshare_api_key_index]
    TAG = "VirusTotalScanMain,"
    _api_request = "http://malshare.com/api.php?api_key=" + malshare_api_key + "&action=getlist"
    _files_inserted_already = set()
    _processed_instances = set()
    if continue_from_existent_data:
        my_logger.log(TAG, "Continuing from existent data.")
        _files_inserted_already.update(get_list_of_inserted_hashes(output_db_handler))
        _processed_instances.update(get_list_of_hashes_which_analysis_was_already_obtained(output_db_handler))
        my_logger.log(TAG, "Now _files_inserted_already list size is: " + str(len(_files_inserted_already)))
        my_logger.log(TAG, "Now _processed_instances list size is: " + str(len(_processed_instances)))
    _seen_hashes = set()
    # _threads_getting_reports = dict()
    # _threads_sending_files_to_scan = dict()
    running = True
    iterations = 0
    while running:
        my_logger.log(TAG, "Iteration: " + str(iterations))
        iterations += 1
        # try:
        _req = requests.get(_api_request).content.decode("utf-8")
        _hashes = _req.split('<br>')
        _seen_hashes.update(set(_hashes))
        _dif = _seen_hashes.difference(_processed_instances)
        #logger.log(TAG, "Different hashes: " + str(_dif))
        if len(_dif) > 0:
            _processing_date = asctime(gmtime(time()))
            my_logger.log(TAG, "Processing date is : " + _processing_date)
            for _hash in _dif:
                my_logger.log(TAG, "Processing hash: " + _hash)
                if _hash.strip() == "":
                    my_logger.log(TAG, "Hash is empty space skiping")
                if _hash.strip() != "":
                    if _hash in _files_inserted_already:
                        my_logger.log(TAG, "Hash was already handled, it might be a hash that was sent to analysis or "
                                           "its iterating over an existent db.")
                    if _hash not in _files_inserted_already:
                        _success, msg = handle_hash(_hash, malshare_output_folder, output_db_handler, True, True,
                                                    _processing_date, None, db_file_address)

                        if _success:
                            my_logger.log(TAG, "Succesfully processed hash, now will get report.")
                            _files_inserted_already.add(_hash)

                    try:
                        result_code, _js = vt_get_report(virustotal_api_key, _hash)
                        my_logger.log(TAG , "Result code is: " + str(result_code))
                    except Exception as h:
                        my_logger.log(TAG , "ERROR getting report: " + str(h.args))

                    if result_code == 1:
                        my_logger.log(TAG, "Report found without scanning file, now inserting.")
                        insertion_successfull, details = insert_scan(output_db_handler, _js)
                        if insertion_successfull:
                            _processed_instances.add(_hash)

                    if result_code == 0:
                        my_logger.log(TAG, "Dont exist report so sending file to scan.")
                        _file_to_scan = os.path.join(malshare_output_folder, _hash)
                        if os.path.getsize(_file_to_scan)/1000.0/1000.0 > 32:
                            my_logger.log(TAG, "File bigger than 32MB can't be sent to VirusTotal")
                            _processed_instances.add(_hash)
                            continue
                        #Thread(target=vt_file_scan, name=_hash, args=[virustotal_api_key, _file_to_scan, db_file_address]).start()
                        vt_file_scan(virustotal_api_key, _file_to_scan, output_db_handler)

                    if result_code == -1:
                        my_logger.log(TAG, "Might got reached the requests on one minute limit by virus total API.")
                        my_logger.log(TAG, "Will use the next virustotal api key in the list.")
                        set_new_virustotal_api_key_index()

                    if result_code == -2:
                        my_logger.log(TAG, "File already queued for analysis.")
                            # _thread = Thread(name=_hash, target=vt_get_report_until_ready, args=[virustotal_api_key,
                            #                                                                     scanid,
                            #                                                                     db_file_address])
                            # _thread.start()
                            # _threads_getting_reports[_hash] = _thread
                            # _processed_instances.append(_hash)
        # except Exception as e:
        #     print("VirusTotalScanMain, ERROR: " + str(e.args))


def insert_tuple(connection, _tuple):
    """
        Insert a tuple to a local malshare database. Returns a tuple with that express the result of the
         operation with a bool variable and a message string : bool, str
        :param _tuple: The tuple info
        :param connection: The database connection handler
        :type _tuple: Malshare_tuple
        :type connection: sqlite3.Connection
        :return: bool, str
    """
    try:
        cursor = connection.cursor()
        stmnt = "INSERT INTO malware(md5,sha1,sha256,ssdeep,file_type,date_posted) VALUES (?,?,?,?,?,?);"
        stmnt_s = "INSERT INTO source(md5, source) VALUES (?,?);"
        stmnt_d = "INSERT INTO download(md5, download_date, pc_address_download, magic_file_type) VALUES (?,?,?,?)"

        cursor.execute(stmnt,
                       [_tuple.md5, _tuple.sha1, _tuple.sha256, _tuple.ssdeep, _tuple.file_type, _tuple.date_posted])
        connection.commit()
        for source in _tuple.sources:
            cursor.execute(stmnt_s, [_tuple.md5, source])
            connection.commit()
        if _tuple.date_downloaded is not None:
            cursor.execute(stmnt_d, [_tuple.md5, _tuple.date_downloaded, _tuple.pc_address_download,
                                     _tuple.magic_file_type])
            connection.commit()
        return True, "Successfully inserted tuple"
    except Exception as e:
        return False, "Error inserting tuple: " + str(e.args)


def get_last_date_inserted(here):
    '''
    The idea is use this date to start inserting from there on
    :param here: Database connection handler
    :type here: sqlite3.Connection
    :return: str
    '''
    _cursor = here.cursor()
    n = _cursor.execute("SELECT count(*) FROM malware").fetchone()[0]
    stmnt = "SELECT date_posted FROM malware WHERE mid = ?"
    _date = _cursor.execute(stmnt, [str(n)]).fetchone()[0]
    return str(_date)


def get_elements_inserted_by_date(_date, here):
    '''
    Returns a list with the md5 hash of the elements inserted on the database on the specified date
    :param _date: String of date to look for formatted with the default format specified on the python time documentation
    :param here: Database connection handler
    :type _date: str
    :type here: sqlite3.Connection
    :return: list
    '''
    _cursor = here.cursor()
    stmnt = "SELECT md5 FROM malware WHERE date_posted = ?"
    _md5s = _cursor.execute(stmnt, [_date]).fetchall()
    return _md5s


def testing_get_elements_inserted_by_date():
    con = connect_to_database("malshare.db")
    _date = get_last_date_inserted(con)
    md5s = get_elements_inserted_by_date(_date, con)
    print(md5s)


def is_apikey_valid(api_key):
    """
    Makes a request to validate the api key provided.
    Returns an int with either one of the following values:
      1 if is valid
      0 if could not determinate
      -1 if is not valid
    :param api_key:
    :type api_key: str
    :return: int
    """
    _url = "http://malshare.com/api.php?api_key=" + api_key + "&action=getlist"
    TAG = "ValidatingMalshareApiKey"
    my_logger.log(TAG, "Api_key is : " + api_key)
    try:
        r = requests.get(_url)
        if r.ok:
            #my_logger.log(TAG, "Response is: " + str(r.content))
            if "ERROR" not in r.content.decode("utf-8"):
                my_logger.log(TAG, "Api key is valid.")
                return 1
            my_logger.log(TAG, "APi key is not valid")
            return -1
        my_logger.log(TAG, "Api key is not valid.")
        return 0
    except requests.exceptions.ConnectionError:
        my_logger.log(TAG, "ERROR: Seems like there is not network connection.")
        sys.exit(2)


def is_virustotal_apikey_valid(api_key):
    """
    Makes a request to validate the virustotal api key provided.
    Returns an int with either one of the following values:
      1 if is valid
      0 if could not determinate
      -1 if is not valid
    :param api_key:
    :type api_key: str
    :return: int
    """
    TAG = "ValidatingVirusTotalApiKey"
    my_logger.log(TAG, "API key is: " + api_key)
    try:
        _request_url = VIRUS_TOTAL_REPORT_REQUEST_URL
        _params = {'apikey': api_key, 'resource': MD5_FOR_TESTS}
        _response = requests.get(_request_url, params=_params)
        if not _response.ok:
            my_logger.log(TAG, "Network error, couldnt connect with the URL")
            return 0, json.loads('{"error": "Network error, couldnt connect with the URL"}')
        if _response.content == "":
            my_logger.log(TAG, "Api key is not valid.")
            return -1, ""
        my_logger.log(TAG, "Api key is valid.")
        return 1, ""
    except Exception as e:
        my_logger.log(TAG, "ERROR: " + str(e.args))
        return 0, json.loads('{"error":"' + str(e.args) + '"}')


def is_date_valid(date):
    """
    Take a date string and validate it to be in the format %Y %m %d
    %Y  Year with century as a decimal number.
    %m  Month as a decimal number [01,12].
    %d  Day of the month as a decimal number [01,31].
    :param date: String with a date
    :type date: str
    :return: boolean
    """

    from time import strptime

    try:
        #print("Validating date: " + date)
        a = strptime(date, "%Y %m %d")
        #print("Date is: " + str(a))
    except ValueError:
        return False
    return True


def real_extraction(api_key, starting_date=None, ending_date=None, _output_db=None, _pc_address=".",
                    _type_of_files=None, _download_enabled=None, _register_enabled=None, _continue_downloading=False,
                    _notify_after=None):

    TAG = "Extraction"
    if starting_date is not None:
        starting_date = strptime(starting_date, "%Y %m %d")
    if ending_date is not None:
        ending_date = strptime(ending_date, "%Y %m %d")

    if starting_date is None:
        starting_date = strptime(FIRST_DATE_IN_MALSHARE, "%Y %m %d")
    if ending_date is None:
        ending_date = gmtime(time())

    if _download_enabled is None and _register_enabled is None:
        _register_enabled = True

    if _output_db is None:
        my_logger.log(TAG, "Output db is None, using db name: " + DB_ADRESS)
        _output_db = connect_to_database(DB_ADRESS)
    my_cursor = _output_db.cursor()
    _start_from_this_hash = ""

    if _continue_downloading:
        my_logger.log(TAG, "Continue downloading enabled")
        _get_date_query = "SELECT date_posted, md5 FROM malware WHERE md5 = (SELECT md5 FROM malware WHERE mid = " \
                          "(SELECT MAX(mid) FROM malware))"
        try:
            _last_instance = my_cursor.execute(_get_date_query).fetchone()
            if _last_instance is None:
                raise Exception("Last instance is None")
            my_logger.log(TAG, "Last instance found is: " + str(_last_instance[0]))
            _start_from_this_hash = _last_instance[1]
            starting_date = strptime(str(_last_instance[0]), "%Y %m %d")
            my_logger.log(TAG, "Found instances in the db and continue downloading enabled so ignoring previous set starting date")
        except Exception as e:
            my_logger.log(TAG, "Error finding last instance: " + str(e.args))
            my_logger.log(TAG, "Ignoring continue downloading flag")
            _continue_downloading = False

    _processing_date = starting_date
    quantity_of_correctly_downloads = 0
    quantity_of_correctly_registered = 0
    proccesed = 0
    counter = 0
    seconds_of_a_day = 24 * 60 * 60
    _time_lapse = time()
    while mktime(_processing_date) <= mktime(ending_date):
        # print("Processing date: " + asctime(_processing_date))
        l = get_hashlist_from_date(_processing_date.tm_year, _processing_date.tm_mon, _processing_date.tm_mday)
        for _hash in l:
            # print("Processing hash: " + _hash)
            if _continue_downloading:
                # print("Continue downloading enabled so Jumping hash: " + _hash)
                if _hash == _start_from_this_hash:
                    # print("Continue downloading enabled, found last hash, next will be processed.")
                    _continue_downloading = False
                continue
            #_date_to_db = str(_processing_date.tm_year) + " " + str(_processing_date.tm_mon) + " " + str(_processing_date.tm_mday)
            _date_to_db = strftime(_processing_date)
            _result_handling, _m = handle_hash(_hash, _pc_address, api_key, _output_db, _register_enabled, _download_enabled, _date_to_db, _type_of_files)
            # print("Hash handled, result is: " + str(_result_handling))
            # print("Hash handled, messages are: " + str(_m))
            if _download_enabled and _result_handling['download_ok']:
                quantity_of_correctly_downloads += 1
            if _register_enabled and _result_handling['register_ok']:
                quantity_of_correctly_registered += 1
            proccesed += 1
            counter += 1
            if _notify_after is not None:
                if counter == _notify_after:
                    _time_pause = time() - _time_lapse
                    my_logger.log(TAG, "Quantity of successful downloads: " + str(quantity_of_correctly_downloads))
                    my_logger.log(TAG, "Quantity of successful registers: " + str(quantity_of_correctly_registered))
                    my_logger.log(TAG, "Instances processed: " + str(proccesed) + " in: " + str(_time_pause) + " seconds.")
                    counter = 0
                    _time_lapse = time()
        _processing_date = gmtime(mktime(_processing_date) + seconds_of_a_day)


def testing_get_extraction_with_defined_date():
    con = connect_to_database("malshare.db")
    _last_date = get_last_date_inserted(con)
    l = get_elements_inserted_by_date(_last_date, con)
    real_extraction(strptime(_last_date), l)


if __name__ == "__main__":
    # vt_file_scan("e51431ba0e2c49cbbfa247942b3b47d03c475f9d13daaa37a3a58e0466296fc2", "vstestfolder/1f3cda4e3ee6a0b7d9df8ba839fc8887", 'dbtest')
    main(sys.argv[1:])
#
# if __name__ == "__main__":
#     code, js = vt_get_report("e51431ba0e2c49cbbfa247942b3b47d03c475f9d13daaa37a3a58e0466296fc2",
#                              "00c22bba2c767f5bdc5ea9eaa139e221")
#     if code == 1:
#         for _item in js['scans'].items():
#             print("Antivirus: " + _item[0])
#             _values = _item[1]
#             print("\tDetected: " + str(_values['detected']) + "\n")
#             print("\tVersion: " + _values['version'] + "\n")
#             print("\tResult: " + str(_values['result']) + "\n")
#             print("\tUpdate: " + _values['update'] + "\n")