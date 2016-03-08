                            MALSHARE CRAWLER

A CGI program that consumes from the malshare.com API alowing to obtain info and to download malware samples.
Also is used the API of VirusTotal to obtain results of antivirus scannings on those files. One of the functions
developed on this project download the files on malshare.com and submit it to virustotal for scanning on a eternal loop
so can be studied whats the effectiveness of those antivirus on new malwares.

What has been used:
   
    - Python requests
    - Threading
    - Text Parsing
    - Text encoding and decoding
    - File handling (read and write)
    - Json Parsing
    - Working with directories and paths
    - Working with console commands (getopt, sys)
    - Exception handling
    - Sqlite 