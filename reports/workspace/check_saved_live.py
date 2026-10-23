import json,collections
from pathlib import Path
r=[json.loads(l) for l in open('logs/launcher/validation_detections.jsonl')];a=0;out=[]
for name,n in zip(['BENIGN','Brute Force','DDoS','DoS','Port Scan'],[595,9,382,50,123]):
 x=r[a:a+n];a+=n;o=[d for d in x if d.get('first_packet_flags')=='S'];c=collections.Counter(d['genuine_predicted_class'] for d in o);out.append({'profile':name,'flows':n,'opening':len(o),'matches':c[name],'match_rate':c[name]/len(o),'classes':dict(c),'min_start':min(d['start_time'] for d in x),'max_start':max(d['start_time'] for d in x)})
Path('reports/workspace/saved_live_reconciliation.json').write_text(json.dumps({'method':'Consecutive file blocks using per-profile total-flow counts in saved validation_report.txt; corroborates counts but original ProfileWindow objects are not persisted.','groups':out},indent=2))
