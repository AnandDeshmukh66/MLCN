import os,json
from pathlib import Path
os.environ['MPLCONFIGDIR']=str(Path('reports/workspace/mplconfig').resolve())
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch,FancyArrowPatch
import numpy as np
W=Path('reports/workspace');F=W/'figures';A=json.loads((W/'audit_results.json').read_text());C=json.loads((W/'curves.json').read_text())
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False,'savefig.dpi':300})
blue='#174e75';teal='#187c80';gold='#b67a25';gray='#536474'
def save(fig,name):
 fig.savefig(F/(name+'.png'),bbox_inches='tight',facecolor='white',dpi=300);fig.savefig(F/(name+'.svg'),bbox_inches='tight',facecolor='white');plt.close(fig)
def diagram(name,nodes,edges,size=(8,4)):
 fig,ax=plt.subplots(figsize=size);ax.set(xlim=(0,10),ylim=(0,6));ax.axis('off')
 for i,(x,y,w,h,label,kind) in enumerate(nodes):
  ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=.06,rounding_size=.1',edgecolor=gold if kind=='proposed' else blue,facecolor='#fff9eb' if kind=='proposed' else '#f0f6fa',linestyle='--' if kind=='proposed' else '-',linewidth=1.2,zorder=2))
  ax.text(x+w/2,y+h/2,label,ha='center',va='center',fontsize=10,zorder=3)
 for a,b in edges:
  x,y,w,h,*_=nodes[a];X,Y,V,H,*_=nodes[b];dx=X+V/2-(x+w/2);dy=Y+H/2-(y+h/2)
  if abs(dx)>abs(dy):st=(x+w if dx>0 else x,y+h/2);en=(X if dx>0 else X+V,Y+H/2)
  else:st=(x+w/2,y+h if dy>0 else y);en=(X+V/2,Y if dy>0 else Y+H)
  ax.add_patch(FancyArrowPatch(st,en,arrowstyle='-|>',mutation_scale=12,color=gray,shrinkA=4,shrinkB=4,connectionstyle='arc3',zorder=1))
 save(fig,name)
diagram('architecture',[(.2,4.3,2.4,1,'Streamlit controls\nLoopback lab profiles',''),(3.7,4.3,2.4,1,'LabEchoServer\nSocket / HTTP replies',''),(7.2,4.3,2.4,1,'Scapy capture\nSelected interfaces',''),(7.2,2.2,2.4,1,'Parse → flows\n24 contract features',''),(3.7,2.2,2.4,1,'Saved XGBoost\nFive probabilities',''),(.2,2.2,2.4,1,'Genuine results\nCLI / JSONL',''),(.2,.1,2.4,1,'Dashboard reader\nSource-aware review',''),(3.7,.1,2.4,1,'Demo display branch\nSynthetic if enabled',''),(7.2,.1,2.4,1,'Gemini narrative\nProposed only','proposed')],[(0,1),(1,2),(2,3),(3,4),(4,5),(5,6),(5,7),(7,6),(5,8)],(8,4.6))
diagram('pipeline',[(.5,4.6,4,1,'M1 · PacketCaptureEngine\nRaw Scapy packets',''),(5.5,4.6,4,1,'M2 · parse_packet\nPacketMetadata',''),(5.5,2.6,4,1,'M3 · FlowBuilder\nCompleted bidirectional Flow',''),(.5,2.6,4,1,'M4 · FeatureEngineeringEngine\nOrdered FeatureVector (24)',''),(.5,.6,4,1,'M5 · MLDetectionEngine\nDetectionResult (five classes)',''),(5.5,.6,4,1,'PipelineResult\nFlow + features + prediction','')],[(0,1),(1,2),(2,3),(3,4),(4,5)],(8,4.5))
diagram('packet_flow',[(.3,4.5,2.7,1,'IP / TCP / UDP\nRaw packet + timestamp',''),(3.7,4.5,2.7,1,'Normalize addresses,\nports and lengths',''),(7.1,4.5,2.6,1,'Immutable\nPacketMetadata',''),(7.1,2.4,2.6,1,'Canonical key\nLookup active flow',''),(3.7,2.4,2.7,1,'Append packet\nUpdate counters',''),(.3,2.4,2.7,1,'FIN / age / idle /\neviction / flush',''),(.3,.4,2.7,1,'Completed Flow\nPacket tuple retained',''),(3.7,.4,2.7,1,'TCP or UDP?\nAt least two packets?',''),(7.1,.4,2.6,1,'Eligible → features\nOtherwise skipped','')],[(0,1),(1,2),(2,3),(3,4),(4,5),(5,6),(6,7),(7,8)],(8,4.8))
diagram('bidirectional',[(.3,4.4,3.3,1,'A:50001 → B:8080\nFirst observed packet',''),(6.4,4.4,3.3,1,'B:8080 → A:50001\nReply packet',''),(3.2,2.5,3.6,1,'Sort endpoint pairs\nSame FlowKey + protocol',''),(.3,.5,4.2,1,'Forward / reverse orientation\nSeparate from key ordering',''),(5.5,.5,4.2,1,'Feature engine sorts timestamps\nEarliest packet anchors direction','')],[(0,2),(1,2),(2,3),(3,4)],(8,3.8))
diagram('features',[(.3,4.5,2.8,1,'Sort timestamps\nInteger microseconds',''),(3.6,4.5,2.8,1,'Directional payloads\nCounts and sums',''),(6.9,4.5,2.8,1,'Gaps / sample SD\nActive and idle spans',''),(.3,2.4,2.8,1,'First-packet flag map\nDataset compatibility',''),(3.6,2.4,2.8,1,'Rates use seconds\nZero-duration medians',''),(6.9,2.4,2.8,1,'Length series n + 1\nInteger direction ratio',''),(2.7,.3,4.6,1,'Exactly 24 ordered finite values\nFloat32 conversion at inference','')],[(0,1),(1,2),(0,3),(1,4),(2,5),(3,6),(4,6),(5,6)],(8,4.3))
diagram('inference',[(.4,4.5,4,1,'Model JSON + metadata\nValidate feature / class names',''),(5.6,4.5,4,1,'FeatureVector or sequence\n24 finite numeric entries',''),(5.6,2.5,4,1,'Float32 → DMatrix\nNamed feature columns',''),(.4,2.5,4,1,'521 boosting rounds\nmulti:softprob',''),(.4,.5,4,1,'Five class probabilities\nArgmax class + max score',''),(5.6,.5,4,1,'Genuine DetectionResult\nNo attribution generated','')],[(0,3),(1,2),(2,3),(3,4),(4,5)],(8,4.2))
diagram('generator',[(.3,4.5,2.8,1,'Profile medians\nReference JSON',''),(3.6,4.5,2.8,1,'Parameter mapping\nController / limits',''),(6.9,4.5,2.8,1,'Socket generator\nLoopback lab target',''),(6.9,2.4,2.8,1,'Receiver replies\nScapy observes packets',''),(3.6,2.4,2.8,1,'Real M1–M5 pipeline\nGenuine predictions',''),(.3,2.4,2.8,1,'Detection JSONL\nSeparate genuine fields',''),(.3,.3,2.8,1,'Dashboard reader\nLast 512,000 bytes',''),(3.6,.3,2.8,1,'Profile comparison\nOpening-flow fraction',''),(6.9,.3,2.8,1,'Generator run log\nConnection / byte counts','')],[(0,1),(1,2),(2,3),(3,4),(4,5),(5,6),(5,7),(2,8)],(8,4.4))
diagram('training',[(.3,4.5,2.8,1,'Eight local CIC CSVs\n2,830,743 raw rows',''),(3.6,4.5,2.8,1,'Clean / map labels\nSelect 24 columns',''),(6.9,4.5,2.8,1,'Stratified row split\n80 / 10 / 10, seed 42',''),(6.9,2.4,2.8,1,'Training only\nUndersample + weight',''),(3.6,2.4,2.8,1,'Fit XGBoost\nValidation early stop',''),(.3,2.4,2.8,1,'Save model + schema\nBest iteration 520',''),(.3,.3,2.8,1,'Saved test features\n251,812 rows',''),(3.6,.3,2.8,1,'Audit inference\nNo label disagreements',''),(6.9,.3,2.8,1,'Metrics / ROC / PR\nOffline evidence only','')],[(0,1),(1,2),(2,3),(3,4),(4,5),(5,7),(6,7),(7,8)],(8,4.4))
diagram('gemini',[(.3,4.5,2.8,1,'Genuine model result\nFeature units + provenance',''),(3.6,4.5,2.8,1,'Evidence gate\nReject synthetic records','proposed'),(6.9,4.5,2.8,1,'Minimize / pseudonymize\nValidated JSON contract','proposed'),(6.9,2.4,2.8,1,'Gemini API request\nVersioned prompt + schema','proposed'),(3.6,2.4,2.8,1,'Validate response\nEvidence-ID checks','proposed'),(.3,2.4,2.8,1,'Analyst-facing report\nUncertainty + limitations','proposed'),(.3,.3,2.8,1,'Human review\nNo autonomous blocking','proposed'),(3.6,.3,2.8,1,'Optional SHAP adapter\nOnly computed attributions','proposed'),(6.9,.3,2.8,1,'Failure path\nDeterministic factual summary','proposed')],[(0,1),(1,2),(2,3),(3,4),(4,5),(5,6),(7,1),(3,8)],(8,4.5))
cl=A['classes'];rep=A['classification_report'];support=[rep[c]['support'] for c in cl]
fig,ax=plt.subplots(figsize=(7,3.6));bars=ax.bar(cl,support,color=[blue,gold,teal,gray,'#6f6b99']);ax.set_yscale('log');ax.set_ylabel('Test rows (log scale)');ax.set_ylim(100,700000)
for b,v in zip(bars,support):ax.text(b.get_x()+b.get_width()/2,v*1.15,f'{int(v):,}\n({v/sum(support):.2%})',ha='center',fontsize=10,zorder=3)
save(fig,'distribution')
fig,ax=plt.subplots(figsize=(7,3.5));x=np.arange(5)
for j,(k,label,col) in enumerate([('precision','Precision',blue),('recall','Recall',teal),('f1-score','F1',gold)]):ax.bar(x+(j-1)*.24,[rep[c][k] for c in cl],width=.23,label=label,color=col)
ax.set_xticks(x,cl);ax.set_ylim(0,1.12);ax.set_ylabel('Score');ax.legend(loc='lower left',ncol=3);save(fig,'performance')
cm=np.array(A['confusion_matrix']);fig,ax=plt.subplots(figsize=(7,4.5));im=ax.imshow(np.log10(cm+1),cmap='Blues');ax.set_xticks(range(5),cl,rotation=25,ha='right');ax.set_yticks(range(5),cl);ax.set_xlabel('Predicted class');ax.set_ylabel('Actual class')
for i in range(5):
 for j in range(5):ax.text(j,i,f'{cm[i,j]:,}',ha='center',va='center',color='white' if cm[i,j]>5000 else 'black',fontsize=10)
fig.colorbar(im,ax=ax,label='Colour: log10(count + 1)',shrink=.8);save(fig,'confusion')
fig,ax=plt.subplots(figsize=(7,4));
for c in cl:ax.plot(C[c]['fpr'],C[c]['tpr'],label=f"{c} ({A['per_class_auc'][c]:.6f})",lw=1.5)
ax.plot([0,1],[0,1],color='gray',ls='--',lw=.7);ax.set(xlabel='False positive rate',ylabel='True positive rate',xlim=(0,1),ylim=(0,1.02));ax.legend(loc='lower right',fontsize=10,title='One-vs-rest ROC AUC');save(fig,'roc')
fig,ax=plt.subplots(figsize=(7,4));
for c in cl:ax.plot(C[c]['recall'],C[c]['precision'],label=f"{c} (AP {A['per_class_ap'][c]:.5f})",lw=1.4)
ax.scatter([rep['Brute Force']['recall']],[rep['Brute Force']['precision']],color='black',s=25,zorder=5,label='Brute Force multiclass argmax point')
ax.set(xlabel='Recall',ylabel='Precision',xlim=(0,1.01),ylim=(0,1.04));ax.legend(loc='lower left',fontsize=10);save(fig,'pr')
fig,ax=plt.subplots(figsize=(7,3.5));x=np.arange(5);ax.bar(x-.18,[298,4,188,23,115],.36,label='Matching opening flows',color=teal);ax.bar(x+.18,[298,5,190,24,119],.36,label='Opening flows reported',color=gray);ax.set_xticks(x,cl);ax.set_ylabel('Flow count');ax.legend();save(fig,'live_counts')
print('Generated',len(list(F.glob('*.svg'))),'original figures')
