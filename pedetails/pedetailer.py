__author__ = 'yalu'

import sqlite3
import time
try:
    import pefile
    import peutils
    PEFILE = True
except ImportError:
    print("Error Importing pefile and peutils")
    PEFILE = False
try:
    import magic
    MAGIC = True
except:
    print("Error Importing Magic")
    MAGIC = False
import os
from logger import Logger




class PeFile:
    def __init__(self, md5, sha1, sha256, sha512, imp_hash, compilation_date, suspicious, pesections,
                 peimports, peexports):
        self.md5, self.sha1, self.sha256, self.sha512, self.imp_hash, self.compilation_date, self.suspicious,\
        self.pesections, self.peimports, self.peexports = md5, sha1, sha256, sha512, imp_hash, compilation_date, \
                                                          suspicious, pesections, peimports, peexports


class PEDetailer():

    def __init__(self, pe_db_address=None, logger=None):
        self.logger = logger
        if self.logger is None:
            self.logger = Logger()
        self.pe_db_address = pe_db_address
        if self.pe_db_address is None:
            self.pe_db_address = "pedb.db"
        self.pe_db = self.pe_connect_to_database(self.pe_db_address)

    def pe_connect_to_database(self, here):
        """
            Connect to a database if exists else create it.
            Create a db structure to insert the info from PE Files.
            Returns the connection handler.
            :param here: String of the place where the database will be created
            :type here: str
            :return: sqlite3.Connection
            """
        con = sqlite3.connect(here)
        curs = con.cursor()
        try:
            curs.execute("SELECT md5 FROM pefile LIMIT 1")
            return con
        except sqlite3.OperationalError:
            pass
        script = [
            "CREATE TABLE IF NOT EXISTS pefile(md5 VARCHAR, sha1 VARCHAR , sha256 VARCHAR , sha512 VARCHAR , imp_hash VARCHAR , compilation_date VARCHAR , suspicious INTEGER)",
            " CREATE TABLE IF NOT EXISTS pesection(nome VARCHAR , tamanho VARCHAR , md5 VARCHAR )",
            "CREATE TABLE IF NOT EXISTS peimport(md5 VARCHAR , address VARCHAR , nome VARCHAR , dll VARCHAR )",
            "CREATE TABLE IF NOT EXISTS peexport(md5 VARCHAR , address VARCHAR , nome VARCHAR , ordinal VARCHAR )"
        ]
        for stmnt in script:
            curs.execute(stmnt)
            con.commit()
        return con



    def insert_pe_file(self, pefile_obj):
        '''
        Insert pefile row on db.
        :param pefile_obj: PeFile
        :return: bool
        '''
        cursor = self.pe_db.cursor()
        cursor.execute("INSERT INTO pefile (md5, sha1, sha256, sha512, imp_hash, compilation_date, suspicious) "
                       "VALUES(?,?,?,?,?,?,?) ", [pefile_obj.md5, pefile_obj.sha1, pefile_obj.sha256, pefile_obj.sha512,
                                                    pefile_obj.imp_hash, pefile_obj.compilation_date, pefile_obj.suspicious,
                                                    ])
        self.pe_db.commit()
        for _section in pefile_obj.pesections:
            cursor.execute("INSERT INTO pesection(nome, tamanho, md5) VALUES (?,?,?)", [_section['name'], _section['size'],
                                                                                        pefile_obj.md5])
        for _import in pefile_obj.peimports:
            cursor.execute("INSERT INTO peimport(md5, address, nome, dll) VALUES (?, ?, ?, ?)", [pefile_obj.md5,
                                                                                                 _import['address'],
                                                                                                 _import['name'],
                                                                                                 _import['dll']])

        for _export in pefile_obj.peexports:
            cursor.execute("INSERT INTO peexport(md5, address, nome, ordinal) VALUES (?,?,?,?)", [pefile_obj.md5,
                                                                                                  _export['address'],
                                                                                                  _export['name'],
                                                                                                  _export['ordinal']])
        self.pe_db.commit()

    def analyse_pe_file(self, file):
        TAG = "Analysing PE File"
        self.logger.log(TAG, file)
        if not os.path.exists(file):
            self.logger.log(TAG ,"Error, Especified file dont exists")
            return False, "Especified file don't exists"
        if PEFILE:
            try:
                pe = pefile.PE(file)
            except pefile.PEFormatError:
                self.logger.log(TAG, "Error, Not a PE File")
                return False, 'Not PE file'

            md5 = pe.sections[0].get_hash_md5()
            sha1 = pe.sections[0].get_hash_sha1()
            sha256 = pe.sections[0].get_hash_sha256()
            sha512 = pe.sections[0].get_hash_sha512()
            imp_hash = ""
            compilation_date = ""
            suspicious = False
            _pesections = list()
            _peimports = list()
            _peexports = list()
            _filetype = ""
            try:
                imp_hash = pe.get_imphash()
            except:
                pass

            if pe.FILE_HEADER.TimeDateStamp:
                val = pe.FILE_HEADER.TimeDateStamp
                ts = '0x%-8X' % (val)
                try:
                    ts += ' [%s UTC]' % time.asctime(time.gmtime(val))
                    that_year = time.gmtime(val)[0]
                    this_year = time.gmtime(time.time())[0]
                    if that_year < 2000 or that_year > this_year:
                        ts += " [SUSPICIOUS]"
                except:
                    suspicious = True
                    ts += ' [SUSPICIOUS]'
                if ts:
                    compilation_date = ts

            if pe.sections:
                for section in pe.sections:
                    _pesections.append({"name": section.Name, "size": section.SizeOfRawData})

            if pe.DIRECTORY_ENTRY_IMPORT:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        _import = {"address": hex(imp.address), "name": imp.name, "dll": entry.dll}
                        _peimports.append(_import)

            try:
                if pe.IMAGE_DIRECTORY_ENTRY_EXPORT.symbols:
                    for exp in pe.IMAGE_DIRECTORY_ENTRY_EXPORT.symbols:
                        _peexports.append({"address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), "name": exp.name,
                                           "ordinal": exp.ordinal})
            except:
                pass

            self.insert_pe_file(PeFile(md5,sha1,sha256,sha512,imp_hash, compilation_date, suspicious,_pesections,
                                       _peimports, _peexports))
            self.logger.log(TAG, "PE file details inserted succesfully")
            return True, "PE file details inserted succesfully"
        else:
            self.logger.log(TAG, "PeUtils not installed")
            return False, "PeUtils not installed"

# if __name__ == "__main__":
#     _head = "../vstestfolder/"
#     p = PEDetailer(logger=Logger("pelogs"))
#     for _file in os.listdir(_head):
#         p.analyse_pe_file(_head + _file)