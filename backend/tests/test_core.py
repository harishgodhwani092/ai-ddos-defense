from backend.app.detection.threshold_engine import ThresholdEngine
from backend.app.detection.decision_engine import decide
from backend.app.mitigation.firewall_manager import FirewallManager
from backend.app.config import Settings

def test_threshold_flags_spike():
 e=ThresholdEngine(10,2)
 for x in [100,102,98,101]: e.evaluate(x)
 assert e.evaluate(500)['flagged']
def test_allowlist_never_blocks():
 s=Settings(); s.dry_run=True; r=FirewallManager(s).block('127.0.0.1','test'); assert r['status']=='REJECTED_ALLOWLIST'
def test_decision_high():
 r=decide({'syn_rate':100},{'ratio':4,'flagged':True},{'prediction':'DDOS','confidence':.95,'top_indicators':[]}); assert r['prediction']=='DDOS' and r['severity']=='HIGH'
