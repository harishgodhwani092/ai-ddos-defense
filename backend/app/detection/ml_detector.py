import os, joblib
from .threshold_engine import ThresholdEngine
from ..capture.feature_extractor import FEATURES
class MLDetector:
    def __init__(self,path):
        self.path=path; self.model=None; self.version='unavailable'
        if os.path.exists(path): self.model=joblib.load(path); self.version=getattr(self.model,'version','trained-model')
    def predict(self, features):
        if not self.model: return {'prediction':'SUSPICIOUS','confidence':0.0,'model_version':'unavailable','top_indicators':[]}
        x=[[features.get(f,0) for f in FEATURES]]; pred=str(self.model.predict(x)[0]).upper(); probs=getattr(self.model,'predict_proba',lambda z: [[1]])(x)[0]; conf=float(max(probs))
        return {'prediction':pred,'confidence':conf,'model_version':self.version,'top_indicators':self.indicators(features)}
    def indicators(self,f):
        return [x[0] for x in [('packet rate elevated',f.get('packets_per_second',0)>200),('SYN rate elevated',f.get('syn_rate',0)>50),('source frequency abnormal',f.get('source_ip_frequency',0)>20)] if x[1]][:3]
