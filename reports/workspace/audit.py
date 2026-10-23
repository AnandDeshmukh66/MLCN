import os,sys,json,hashlib,ast,time,platform,collections
from pathlib import Path
import numpy as np,pandas as pd,xgboost as xgb
from sklearn import metrics
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));os.chdir(ROOT)
out=ROOT/'reports/workspace'; rows=[]
for p in sorted(ROOT.rglob('*')):
 if not p.is_file() or any(x in p.relative_to(ROOT).parts for x in ['.git','.venv','macvenv','reports','__pycache__','.DS_Store']):continue
 b=p.read_bytes(); item={'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 if p.suffix=='.py':
  t=ast.parse(b);item['symbols']=[n.name for n in ast.walk(t) if isinstance(n,(ast.FunctionDef,ast.ClassDef))];item['doc']=ast.get_docstring(t)
 rows.append(item)
(out/'repository_inventory.json').write_text(json.dumps(rows,indent=2))
meta=json.load(open('models/xgboost_ids_features.json')); df=pd.read_csv('models/xgboost_test_predictions.csv');cl=meta['classes'];f=meta['features']
y=df.Actual.to_numpy();saved=df.Predicted.to_numpy(); yi=np.array([cl.index(v) for v in y]);
b=xgb.Booster();b.load_model('models/xgboost_ids_multiclass.json');b.set_param({'nthread':4})
dm=xgb.DMatrix(df[f].to_numpy(dtype=np.float32),feature_names=f)
t0=time.perf_counter();probs=b.predict(dm,iteration_range=(0,521));elapsed=time.perf_counter()-t0
pred=np.array(cl)[probs.argmax(1)]; cm=metrics.confusion_matrix(y,saved,labels=cl)
r={'environment':{'python':sys.version,'platform':platform.platform(),'xgboost':xgb.__version__},'files':len(rows),'samples':len(df),'features':f,'classes':cl,'finite_features':bool(np.isfinite(df[f]).all().all()),'booster_rounds':b.num_boosted_rounds(),'booster_attrs':b.attributes(),'accuracy':metrics.accuracy_score(y,saved),'balanced_accuracy':metrics.balanced_accuracy_score(y,saved),'classification_report':metrics.classification_report(y,saved,labels=cl,output_dict=True),'confusion_matrix':cm.tolist(),'saved_confusion_agrees':bool(np.array_equal(cm,pd.read_csv('models/xgboost_confusion_matrix.csv',index_col=0).values)),'regenerated_label_disagreements':int((saved!=pred).sum()),'confidence_max_abs_difference':float(np.max(abs(probs.max(1)-df.Confidence))),'roc_auc_macro':metrics.roc_auc_score(yi,probs,multi_class='ovr',average='macro'),'roc_auc_weighted':metrics.roc_auc_score(yi,probs,multi_class='ovr',average='weighted'),'log_loss':metrics.log_loss(yi,probs),'batch_inference_seconds':elapsed,'correct_confidence_mean':float(df.loc[y==saved,'Confidence'].mean()),'incorrect_confidence_mean':float(df.loc[y!=saved,'Confidence'].mean()),'per_class_auc':{},'per_class_ap':{}}
curves={}
for i,c in enumerate(cl):
 target=yi==i; r['per_class_auc'][c]=metrics.roc_auc_score(target,probs[:,i]);r['per_class_ap'][c]=metrics.average_precision_score(target,probs[:,i]);fp,tp,_=metrics.roc_curve(target,probs[:,i]);pr,re,_=metrics.precision_recall_curve(target,probs[:,i]);curves[c]={'fpr':fp.tolist(),'tpr':tp.tolist(),'precision':pr.tolist(),'recall':re.tolist()}
(out/'curves.json').write_text(json.dumps(curves));np.savez_compressed(out/'regenerated_probabilities.npz',probabilities=probs)
logs={}
for p in Path('logs').rglob('*.jsonl'):
 rec=[json.loads(l) for l in p.read_text().splitlines() if l.strip()];logs[str(p)]={'records':len(rec),'record_types':dict(collections.Counter(x.get('record_type','flow') for x in rec)),'sources':dict(collections.Counter(x.get('result_source') for x in rec)),'genuine_predictions':dict(collections.Counter(x.get('genuine_predicted_class') for x in rec)),'fallback':sum(bool(x.get('demo_fallback')) for x in rec),'first':rec[:1],'session_records':[x for x in rec if x.get('record_type')=='session_result']}
r['logs']=logs
r['raw_csvs']=[]
for p in sorted(Path('MachineLearningCVE').glob('*.csv')):
 d=pd.read_csv(p,usecols=lambda c:c.strip() in ['Label','Flow Duration']);d.columns=d.columns.str.strip();r['raw_csvs'].append({'file':str(p),'rows':len(d),'labels':d.Label.value_counts().to_dict(),'negative_duration':int((d['Flow Duration']<0).sum())})
(out/'audit_results.json').write_text(json.dumps(r,indent=2));print(json.dumps({k:v for k,v in r.items() if k not in ['logs','raw_csvs','features','classification_report']},indent=2));print('RAW',r['raw_csvs']);print('LOG SUMMARY',{k:{x:y for x,y in v.items() if x not in ['first','session_records']} for k,v in logs.items()})
