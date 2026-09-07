def severity_score(features, threshold, ml):
    anomaly=min(50,max(0,(threshold['ratio']-1)*20)); confidence=ml['confidence']*30; syn=min(20,features.get('syn_rate',0)/10); return round(min(100,anomaly+confidence+syn),1)
def decide(features, threshold, ml, confidence_threshold=.7):
    score=severity_score(features,threshold,ml)
    if ml['prediction']=='DDOS' and ml['confidence']>=confidence_threshold or threshold['ratio']>=3: pred='DDOS'
    elif threshold['flagged'] or ml['prediction'] in ('DDOS','SUSPICIOUS'): pred='SUSPICIOUS'
    else: pred='NORMAL'
    severity='HIGH' if score>=70 else 'MEDIUM' if score>=40 else 'LOW'
    reasons=[]
    if threshold['flagged']: reasons.append(f"packet rate {threshold['ratio']:.1f}x above baseline")
    reasons += ml.get('top_indicators',[])
    if ml['prediction']=='DDOS': reasons.append('ML classifier predicts DDoS')
    return {'prediction':pred,'severity':severity,'severity_score':score,'reasons':reasons or ['traffic within baseline']}
