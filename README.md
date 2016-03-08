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
     
     
Usage is: "mlshrcrawler -s/--starting-date Starting date(%Y %m %d) -e/--ending-date Ending date (%Y %m %d)
                         -o/--output-database Output database address -p/--download-to-address Address in the pc
                          where to download files -t/--file-type Filter for type of file -h/--help
                          -d/--download This option will enable the download.
                          -r/--register This option will enable the register into db -k/--api-key Malshare api key,
                          -q/--apikey-from-file Address of a file containing the Malshare API Key
                          -c/--continue-downloading If specified will look for the last element in the db specified
                          and will continue downloading from the rest elements in that date. -n/--notify-each A number
                          of instances after which the program will notify the status of downloaded and or registered.
                          -v/--last-24h-virus-scan Iniside an infinite loop will download last 24 hours found viruses
                          on malshare dataset, send it to virustotal and register the virus metadata and  results of
                          the scan. -w/--virustotal-apikey Virus total api key, -a/--virustotal-apikey-fromfile Load
                          Virus total api key from specified file address.
                          -f/--verbose-to-file Print results of any operation to file
                          
Command example:

The next command line will start a loop downloading the most recent files uploaded to malshare to the folder specified with -p.
Each of this file are obtained the details (PE details and Magic file type) and the details provided by malshare.
Then is requested virus total to obtain scan results, if the file was not scanned before then is sent to virus total for scanning.
Each api key is provided with the -q and -a selectors. Also the logs will be printed to the file "logs" specified by the selector -f :
    
    ./mlshrcrawler.py -o virustotalscan.db -p vstestfolder -d -r -q my_malshare_api_key -v -a virustotal_apikey -f logs
 