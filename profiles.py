import sqlite3
from typing import List, Dict, Optional

Scan_Profiles = "CREATE TABLE IF NOT EXISTS profiles ( Scan_Profile_ID INTEGER PRIMARY KEY AUTOINCREMENT, Profile_Name TEXT UNIQUE, TargetIP TEXT, Port_Selection TEXT, Timeout REAL, Threads INTEGER, Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP )"

class Profile_Manager:
    def __init__(self, db_path: str = "data.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute(Scan_Profiles)
        self.conn.commit()

    def save_profile(self, name, target, ports, timeout, threads):
        ports_list = ",".join(map(str, ports))

        self.cursor.execute("INSERT INTO profiles (Profile_Name, TargetIP, Port_Selection, Timeout, Threads) VALUES (?, ?, ?, ?, ?)",
                            (name, target, ports_list, timeout, threads))
        
        self.conn.commit()

    def load_profile(self, name):
        self.cursor.execute("SELECT * FROM profiles WHERE Profile_Name = ?", (name,))
        fetchone = self.cursor.fetchone()
        if fetchone:
            profile = {
                "Profile_Name": fetchone[1],
                "TargetIP": fetchone[2],
                "Port_Selection": list(map(int, fetchone[3].split(","))),
                "Timeout": fetchone[4],
                "Threads": fetchone[5],
                "Created_At": fetchone[6]
            }
            return profile
        return None


        #placeholder for parsing port string back to a list

    def list_profiles(self):
        self.cursor.execute("SELECT Profile_Name FROM profiles")
        fetchall = self.cursor.fetchall()
        return [name[0] for name in fetchall]
        #return a list of names

    def delete_profile(self, name):
        self.cursor.execute("DELETE FROM profiles WHERE Profile_Name = ?", (name,))
        self.conn.commit()
