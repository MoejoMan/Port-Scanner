import sqlite3
from typing import List, Dict, Optional

Scan_Profiles = "CREATE TABLE IF NOT EXISTS profiles ( Scan_Profile_ID INTEGER PRIMARY KEY AUTOINCREMENT, Profile_Name TEXT UNIQUE, TargetIP TEXT, Port_Selection TEXT, Timeout REAL, Threads INTEGER, Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP )"

class Profile_Manager:
    def __init__(self, db_path: str = "data.db"):
        pass

    def save_profile(self, name, target, ports, timeout, threads):
        pass

    def load_profile(self, name):
        pass

