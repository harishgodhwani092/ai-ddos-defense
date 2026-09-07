import sqlite3, json, threading
class Database:
 def __init__(self,path): self.path=path; self.lock=threading.Lock(); self.init()
 def init(self):
  with sqlite3.connect(self.path) as c:
   c.executescript('''CREATE TABLE IF NOT EXISTS detection_events(id INTEGER PRIMARY KEY,timestamp TEXT,source_ip TEXT,prediction TEXT,confidence REAL,severity TEXT,severity_score REAL,reason TEXT,model_version TEXT); CREATE TABLE IF NOT EXISTS mitigation_events(id INTEGER PRIMARY KEY,timestamp TEXT,source_ip TEXT,action TEXT,status TEXT,duration INTEGER,reason TEXT); CREATE TABLE IF NOT EXISTS traffic_records(id INTEGER PRIMARY KEY,timestamp TEXT,source_ip TEXT,packet_rate REAL,byte_rate REAL,protocol TEXT);''')
 def add(self,table,data):
  with self.lock,sqlite3.connect(self.path) as c:
   keys=','.join(data); c.execute(f'INSERT INTO {table} ({keys}) VALUES ({",".join("?" for _ in data)})',tuple(data.values())); c.commit()
 def list(self,table,limit=50):
  with sqlite3.connect(self.path) as c: c.row_factory=sqlite3.Row; return [dict(x) for x in c.execute(f'SELECT * FROM {table} ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]
