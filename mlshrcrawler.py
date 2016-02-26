#!/usr/bin/env python3
__author__ = 'yalu'

import os
import requests
import json
import sqlite3
import sys
import getopt
from time import time, mktime, strptime, asctime, gmtime

malshare_types = set()

DB_NAME = "malshare.db"
FIRST_DATE_IN_MALSHARE = "2013 04 06"
# example of daily string: http://malshare.com/daily/year-month-day/malshare_fileList.year-month-day.txt
url_daily_string_head = "http://malshare.com/daily/"
url_string_head = "http://malshare.com/"
url_with_api_string_head = url_string_head + "api.php?api_key="
str_action = "&action="
str_action_get_list_html = str_action + "getlist"
str_action_get_list_raw = str_action + "getlistraw"
str_action_get_list_sources_html = str_action + "getsources"
str_action_get_list_sources_raw = str_action + "getsourcesraw"
str_action_downloadfile = str_action + "getfile&hash="
str_action_details = str_action + "details&hash="
str_action_last24h_md5list_from_file_type = str_action + "type&type="


class Malshare_tuple():
    """
    Class for the instances of tuples to Malshare database.

    """

    def __init__(self, tuple_id=-1, md5="", sha1="", sha256="", ssdeep="", file_type="", sources=list(), date_posted="",
                 date_downloaded="", pc_address_download=""):
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
        :return: Malshare_tuple
        """
        self.tuple_id, self.md5, self.sha1, self.sha256, self.ssdeep, self.file_type, self.sources, self.date_posted, \
        self.date_downloaded, self.pc_address_download = tuple_id, md5, sha1, sha256, ssdeep, file_type, sources, \
                                                         date_posted, date_downloaded, pc_address_download

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
    if len(str(day)) == 1: day = "0" + str(day)
    if len(str(month)) == 1: month = "0" + str(month)
    aux = str(year) + "-" + str(month) + "-" + str(day)
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


def download_file(api_key, _file_hash, destination):
    """
    Download the file specified by hash to the destination specified
    :param api_key:
    :param _file_hash:
    :param destination:
    :return: tuple(bool,str)
    """
    _url = "http://malshare.com/api.php?api_key=" + api_key + "&action=getfile&hash=" + _file_hash
    r = requests.get(_url)
    content = r.content
    _response = ""
    try:
        _response = content.decode('utf-8')
    except Exception:
        pass
    if 'not activated' in _response:
        return False, "Wrong api key"
    if 'Invalid Hash' in _response:
        return False, "Hash found as invalid"
    if not r.ok:
        return False, "Url response code not 200"
    try:
        with open(destination, 'wb') as f:
            f.write(content)
        return True, "File with hash: " + _file_hash + " downloaded to: " + destination
    except Exception as e:
        return False, str(e.args)


def handle_hash(file_hash, destination_address=".", api_key=None, _db_handler=None,
                _register_enabled=True, _download_enabled=False, _processing_date="", _file_type=None):
    """
    Download and/or register a specified hash, by default it only download to the specified address.
    Returns a tuple with a dict and a array, the first with the success or failure on download and register process
    expressed with bool values for download in the first position and for register in the second. The array contains
    the messages logged on each step.
    :param file_hash: Hash of the malware to be handled
    :param destination_address: Address where the file will be downloaded
    :param api_key: Api key to be used with the Malshare API
    :param _db_handler: A handler to the db to be used
    :param _register_enabled: If true will register to a db. Default value is True
    :param _download_enabled: If true will download to the specified address. Default value is False
    :param _file_type: Will handle hash if belong of a file with the type specified by this parameter
    :type _db_handler: sqlite3.Connection
    :return: dict(), []
    """
    TAG = "Handling hash " + file_hash + " "
    _result_messages = []
    _download_correct = False
    _register_correct = False
    _download_date = None
    details = get_file_details_json(file_hash, api_key)
    if _file_type is not None:
        if not _file_type == details["F_TYPE"]:
            return {"download_ok": True, "register_ok": True}, ["Unwanted file type"]
    if _download_enabled:
        if not os.path.exists(destination_address):
            _download_correct = False
            _result_messages.append("Specified path don't exist.")
        else:
            _download_to = os.path.join(os.path.abspath(destination_address), file_hash)
            _download_result = download_file(api_key, file_hash, _download_to)
            _download_correct = _download_result[0]
            _result_messages .append(_download_result[1])
            if _download_correct:
                _download_date = asctime(gmtime(time()))
    if _register_enabled:
        if _db_handler is None:
            _register_correct = False
            _result_messages.append(" Not specified db handler")
        else:
            try:

                t = Malshare_tuple(-1, details.get('MD5'), details.get('SHA1'), details.get('SHA256'), details.get("SSDEEP"),
                                   details.get("F_TYPE"), details.get('SOURCES'), _processing_date, _download_date,
                                   destination_address)
                _inserting_result = insert_tuple(_db_handler, t)
                _register_correct = _inserting_result[0]
                _result_messages.append(_inserting_result[1])
            except Exception as e:
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
    default_json = "{'MD5': 'No information found on malshare.', 'SSDEEP': 'No information found on malshare.', " \
                   "'SOURCES':[] , 'SHA256': 'No information found on malshare.'" \
                   "'SHA1': 'No information found on malshare.', 'F_TYPE': 'No information found on malshare.'}"
    url = url_with_api_string_head + api_key + str_action_details + file_hash
    r = requests.get(url)
    request_content = r.content.decode('utf-8')
    if "Sample not found" not in request_content:
        default_json = request_content
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
        "CREATE TABLE IF NOT EXISTS source(mid INTEGER , source VARCHAR );",
        "CREATE TABLE IF NOT EXISTS download(mid INTEGER , download_date VARCHAR , pc_address_download VARCHAR)"]
    for stmnt in script:
        curs.execute(stmnt)
        con.commit()
    return con


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
        stmnt = "INSERT INTO malware(md5,sha1,sha256,ssdeep,file_type, date_posted) VALUES (?,?,?,?,?,?);"
        stmnt_s = "INSERT INTO source(mid, source) VALUES (?,?);"
        stmnt_d = "INSERT INTO download(mid, download_date, pc_address_download) VALUES (?,?,?)"

        cursor.execute(stmnt,
                       [_tuple.md5, _tuple.sha1, _tuple.sha256, _tuple.ssdeep, _tuple.file_type, _tuple.date_posted])
        _malware_id = cursor.lastrowid
        connection.commit()
        for source in _tuple.sources:
            cursor.execute(stmnt_s, [_malware_id, source])
            connection.commit()
        if not _tuple.date_downloaded.strip() == "":
            cursor.execute(stmnt_d, [_malware_id, _tuple.date_downloaded, _tuple.pc_address_download])
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
    _url = "http://malshare.com//api.php?api_key=ksl&action=getlist"
    r = requests.get(_url)
    if r.ok:
        if not r.content.decode("utf-8") == "ERROR! => Account not activated":
            return 1
        return -1
    return 0


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
        strptime(date, "%Y %m %d")
    except ValueError:
        return False
    return True


def real_extraction(api_key, starting_date=None, ending_date=None, _output_db=None, _pc_address=".",
                    _type_of_files=None, _download_enabled=None, _register_enabled=None, _continue_downloading=False,
                    _notify_after=None):

    if starting_date is None:
        starting_date = mktime(strptime(FIRST_DATE_IN_MALSHARE, "%Y %m %d"))
    if ending_date is None:
        ending_date = time()
    if _download_enabled is None and _register_enabled is None:
        _register_enabled = True
    _processing_date = starting_date
    if _output_db is None:
            _output_db = connect_to_database(DB_NAME)
    my_cursor = _output_db.cursor()
    _start_from_this_hash = ""
    if _continue_downloading:
        _get_date_query = "SELECT date_posted, md5 FROM malware WHERE md5 = (SELECT md5 FROM malware WHERE mid = " \
                          "(SELECT MAX(mid) FROM malware))"
        try:
            _last_instance = my_cursor.execute(_get_date_query).fetchone()
            _start_from_this_hash = _last_instance[1]
            _processing_date = strptime(str(_last_instance[0]))
        except Exception as e:
            pass
    quantity_of_correctly_downloads = 0
    quantity_of_correctly_registered = 0
    proccesed = 0
    counter = 0
    while mktime(_processing_date) <= ending_date:
        l = get_hashlist_from_date(_processing_date.tm_year, _processing_date.tm_mon, _processing_date.tm_mday)
        for _hash in l:
            if _continue_downloading:
                if _hash == _start_from_this_hash:
                    _continue_downloading = False
                continue
            _result_handling, _m = handle_hash(_hash, _pc_address, api_key, _output_db, _register_enabled, _download_enabled
                                           , _processing_date, _type_of_files)
            if _download_enabled and _result_handling['download_ok']:
                quantity_of_correctly_downloads += 1
            if _register_enabled and _result_handling['register_ok']:
                quantity_of_correctly_registered += 1
            proccesed += 1
            counter += 1
            if _notify_after is not None:
                if proccesed == counter:
                    print("Quantity of successful downloads: " + str(quantity_of_correctly_downloads))
                    print("Quantity of successful registers: " + str(quantity_of_correctly_registered))
                    print("Instances processed: " + str(proccesed))
                    counter = 0


def testing_get_extraction_with_defined_date():
    con = connect_to_database("malshare.db")
    _last_date = get_last_date_inserted(con)
    l = get_elements_inserted_by_date(_last_date, con)
    real_extraction(strptime(_last_date), l)


def main(argv):
    """
    This method will handle the input parameters and args and validate each of them.
    Then will pass control to the method real_extraction which do the hard work.
    :param argv:
    :return:
    """

    usage = "mlshrcrawler -s/--starting-date Starting date(%Y %m %d) -e/--ending-date Ending date (%Y %m %d) \n" \
            "             -o/--output-database Output database address -p/--download-to-address Address in the pc  \n" \
            "              where to download files -t/--file-type Filter for type of file -h/--help \n" \
            "              -d/--download This option will enable the download. \n" \
            "              -r/--register This option will enable the register into db -k/--api-key Api key, \n" \
            "              -q/--apikey-from-file Address of a file containing the API Key \n" \
            "              -c/--continue-downloading If specified will look for the last element in the db specified \n" \
            "              and will continue downloading from the rest elements in that date. -n/--notify-each A number \n" \
            "              of instances after which the program will notify the status of downloaded and or registered. \n"

    try:
        opts, args = getopt.getopt(argv, "hs:e:o:p:t:k:q:n:drc", ["help", "starting-date=", "ending-date=",
                                                               "output-database=", "download-to-address=",
                                                                 "file-type=", "download", "register",
                                                                 "api-key=", "apikey-from-file=",
                                                               "continue-downloading", "notify-each="])
    except getopt.GetoptError as e:
        print(e.msg)
        print("Usage is: " + usage)
        sys.exit(2)

    _starting_date = None
    _ending_date = None
    _output_database = None
    _hashes_list = []
    _pc_address_to_download = None
    _type_of_file = None
    _download_enabled = None
    _register_enabled = None
    _continue_downloading = None
    _api_key = None
    _notify_after = None
    if len(opts) == 0:
        print(usage)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Usage is: " + usage)
            sys.exit(1)
        elif opt in ("-s", "--starting-date"):
            if not is_date_valid(arg):
                print("Sorry, seems like date is not valid. Must be in the format %Y %m %d, e.i 2014 04 01")
                sys.exit(2)
            first_date_in_malshare = mktime(strptime(FIRST_DATE_IN_MALSHARE, "%Y %m %d"))
            if mktime(strptime(_starting_date, "%Y %m %d")) < first_date_in_malshare:
                print("The date entered is before the first date in malshare, setting to the first date in malshare: " + FIRST_DATE_IN_MALSHARE)
                _starting_date = FIRST_DATE_IN_MALSHARE
            else:
                _starting_date = arg
        elif opt in ("-e", "--ending-date"):
            if not is_date_valid(arg):
                print("Sorry, seems like date is not valid. Must be in the format %Y %m %d, e.i 2014 04 01")
                sys.exit(2)
            _ending_date = arg
        elif opt in ("-o", "--output-database"):
            con = connect_to_database(arg)
            _output_database = con
        elif opt in ("-p", "--download-to-address"):
            if not os.path.exists(arg):
                print("The specified path is wrong")
                sys.exit(2)
            _pc_address_to_download = arg
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
            _download_enabled = True
        elif opt in ("-r", "--register"):
            _register_enabled = True
        elif opt in ("-q", "--apikey-from-file"):
            try:
                with open(arg) as _f:
                    _api_key = _f.read()
                _valid_api_key = is_apikey_valid(_api_key)
                if _valid_api_key == 1:
                    _api_key = arg
                elif _valid_api_key == 0:
                    print("Couldn't determinate if the provided api key is valid")
                    sys.exit(2)
                elif _valid_api_key == -1:
                    print("Definitely the api key provided is not valid.")
                    sys.exit(2)
            except FileNotFoundError:
                print("Seems like the file with the api key provided don't exist in that address.")
                sys.exit(2)
        elif opt in ("-k", "--api-key"):
            _valid_api_key = is_apikey_valid(_api_key)
            if _valid_api_key == 1:
                _api_key = arg
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
        else:
            print(usage)
            sys.exit(2)
    if _api_key is None:
        print("You must specify an API key for this program to work.")
        sys.exit(2)
    real_extraction(_api_key, _starting_date, _ending_date, _output_database, _pc_address_to_download,
                    _type_of_file, _download_enabled, _register_enabled, _continue_downloading, _notify_after)

if __name__ == "__main__":
    main(sys.argv[1:])