__author__ = 'yalu'

import os
from time import asctime, gmtime, time
import threading

class Logger():

    def __init__(self, file_to_log=None, log_to_console=True):
        # print("Creating logger with file_to_log: " + str(file_to_log))
        self.log_to_console = log_to_console
        self.file_to_log = file_to_log
        _data = asctime(gmtime(time()))
        if self.file_to_log is not None:
            with open(self.file_to_log, 'a') as _f:
                _f.write("\n" + "File opened to log on: " + str(_data) + "\n")

    def log(self, tag="", msg=""):
        _content = tag + " : " + msg
        if self.file_to_log is not None:
            with open(self.file_to_log, 'a') as _f:
                _f.write(_content + "\n")
        if self.log_to_console:
            print(_content)


# def test_logger_on_thread(the_logger, name_of_thread):
#     the_logger.log(name_of_thread, "First Log")
#     the_logger.log(name_of_thread, "Seconf Log")
#
# if __name__ == "__main__":
#     l = Logger(file_to_log="logs")
#     for i in range(4):
#         threading.Thread(target=test_logger_on_thread, args=[l, str(i)]).start()