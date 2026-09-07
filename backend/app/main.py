import os, asyncio, random, json
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .db.database import Database
from .detection.threshold_engine import ThresholdEngine
from .detection.ml_detector import MLDetector
from .detection.decision_engine import decide
from .mitigation.firewall_manager import FirewallManager
from .simulation import Simulation
from .capture.packet_capture import PacketCapture
from .capture.feature_extractor import FeatureExtractor
feature_extractor=FeatureExtractor()
_live_capture=None
app=FastAPI(title='AI-Based Real-Time DDoS Detection and Mitigation System',version='1.0.0'); app.add_middleware(CORSMiddleware,allow_origins=['*'],allow_methods=['*'],allow_headers=['*'])
root=os.path.abspath(os.path.join(os.path.dirname(__file__),'../..')); db=Database(os.path.join(root,settings.db_path)); threshold=ThresholdEngine(settings.threshold_window,settings.sensitivity); detector=MLDetector(os.path.join(root,settings.model_path)); firewall=FirewallManager(settings); clients=set(); state={'monitoring':False,'started_at':None,'latest':None,'packets_per_second':0,'mitigation_enabled':settings.mitigation_enabled,'dry_run':settings.dry_run}
async def broadcast(msg):
 for ws in list(clients):
  try: await ws.send_json(msg)
  except: clients.discard(ws)
async def process(rate=None, raw_records=None):
 if raw_records is not None:
  features=feature_extractor.extract(raw_records, duration=settings.interval).as_dict()
  rate=features['packets_per_second']
  src=raw_records[0].get('source_ip','unknown') if raw_records else 'unknown'
 else:
  flags='S' if rate>200 else 'A'; src='192.0.2.'+str(random.randint(10,30)); features={'packets_per_second':rate,'bytes_per_second':rate*600,'source_ip_frequency':max(1,rate//25),'syn_rate':rate*.8 if rate>200 else rate*.1,'connection_rate':rate*.6,'unique_source_ips':max(1,rate//20)}
 th=threshold.evaluate(rate); ml=detector.predict(features); result=decide(features,th,ml,settings.ml_confidence); now=datetime.now(timezone.utc).isoformat(); action='MONITOR'
 if result['prediction']=='DDOS' and result['severity']=='HIGH':
  m=firewall.block(src,'; '.join(result['reasons'])); action=m['status']; db.add('mitigation_events',{'timestamp':now,'source_ip':src,'action':'BLOCK','status':action,'duration':settings.block_duration,'reason':'; '.join(result['reasons'])})
 db.add('detection_events',{'timestamp':now,'source_ip':src,'prediction':result['prediction'],'confidence':ml['confidence'],'severity':result['severity'],'severity_score':result['severity_score'],'reason':'; '.join(result['reasons']),'model_version':ml['model_version']})
 event={'timestamp':now,'source_ip':src,'rate':rate,'prediction':result['prediction'],'confidence':ml['confidence'],'severity':result['severity'],'score':result['severity_score'],'action':action,'reasons':result['reasons'],'threshold':th}
 state.update({'latest':event,'packets_per_second':rate}); await broadcast({'type':'telemetry','data':event})
async def simulation_loop():
 sim=Simulation(process); sim.start(); return sim
@app.get('/')
def home(): return FileResponse(os.path.join(root,'frontend/index.html'))
@app.get('/api/status')
def status(): return {**state,'model_loaded':detector.model is not None,'model_version':detector.version,'interface':settings.interface,'uptime':state['started_at']}
@app.get('/api/detections')
def detections(): return db.list('detection_events')
@app.get('/api/mitigations')
def mitigations(): return db.list('mitigation_events')
@app.get('/api/statistics')
def statistics(): return {'total_detections':len(db.list('detection_events',10000)),'blocked_ips':len(firewall.adapter.blocks),'model_loaded':detector.model is not None}
@app.post('/api/monitoring/start')
async def start():
 global _live_capture
 loop=asyncio.get_running_loop()
 def on_window(records, duration): asyncio.run_coroutine_threadsafe(process(raw_records=records), loop)
 _live_capture=PacketCapture(settings.interface, settings.interval, on_window)
 _live_capture.start()
 state.update({'monitoring':True,'capture_mode':'live_packet_capture','started_at':datetime.now(timezone.utc).isoformat()})
 return status()
@app.post('/api/monitoring/stop')
async def stop():
 global _live_capture
 if _live_capture: _live_capture.stop()
 state['monitoring']=False
 return status()
@app.post('/api/simulation/start')
async def start_sim(): state['monitoring']=True; await simulation_loop(); return {'started':True}
@app.post('/api/mitigation/enable')
def enable(): state['mitigation_enabled']=True; settings.mitigation_enabled=True; return status()
@app.post('/api/mitigation/disable')
def disable(): state['mitigation_enabled']=False; settings.mitigation_enabled=False; return status()
@app.websocket('/ws')
async def ws(websocket:WebSocket):
 await websocket.accept(); clients.add(websocket)
 try:
  while True: await websocket.receive_text()
 except: clients.discard(websocket)
