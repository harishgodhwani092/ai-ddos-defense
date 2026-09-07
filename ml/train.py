"""Train an honest reproducible demo model. For CIC datasets, replace --csv and map its columns in preprocess.py."""
import argparse, os, json, joblib, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_recall_fscore_support,confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from backend.app.capture.feature_extractor import FEATURES

def demo():
 rng=np.random.default_rng(42); rows=[]
 for label in ['NORMAL','DDOS']:
  for _ in range(400):
   attack=label=='DDOS'; rate=rng.normal(900 if attack else 100,100 if attack else 20)
   rows.append({**{f:0 for f in FEATURES},'packets_per_second':max(1,rate),'bytes_per_second':max(1,rate)*rng.normal(600,30),'source_ip_frequency':rng.normal(35 if attack else 2,4),'syn_rate':rng.normal(rate*.8 if attack else rate*.1,5),'connection_rate':rng.normal(rate*.6 if attack else rate*.2,5),'label':label})
 return pd.DataFrame(rows)
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--csv'); ap.add_argument('--out',default='models/demo_random_forest.joblib'); args=ap.parse_args(); df=demo() if not args.csv else pd.read_csv(args.csv)
 if args.csv:
  if 'label' not in df: raise ValueError('CSV must contain label and feature columns')
  for f in FEATURES:
   if f not in df: df[f]=0
 X=df[FEATURES]; y=df.label.astype(str).str.upper(); Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
 pipe=Pipeline([('impute',SimpleImputer(strategy='median')),('scale',StandardScaler()),('model',RandomForestClassifier(n_estimators=150,random_state=42,class_weight='balanced'))]); pipe.fit(Xtr,ytr); pred=pipe.predict(Xte); p,r,f,_=precision_recall_fscore_support(yte,pred,average='weighted',zero_division=0)
 pipe.version='rf-'+pd.Timestamp.now().strftime('%Y%m%d%H%M'); os.makedirs(os.path.dirname(args.out) or '.',exist_ok=True); joblib.dump(pipe,args.out); metrics={'dataset':'demo synthetic' if not args.csv else args.csv,'rows':len(df),'accuracy':accuracy_score(yte,pred),'precision':p,'recall':r,'f1':f,'confusion_matrix':confusion_matrix(yte,pred).tolist(),'features':FEATURES}; json.dump(metrics,open(args.out+'.metrics.json','w'),indent=2); print(json.dumps(metrics,indent=2))
if __name__=='__main__': main()
