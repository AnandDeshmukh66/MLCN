from pathlib import Path
import fitz,re,json,hashlib
from docx import Document
from docx.oxml.ns import qn
W=Path(__file__).parent;R=W.parent;pdf=fitz.open(R/'MLCN_Final_Mini_Project_Report.pdf');D=Document(R/'MLCN_Final_Mini_Project_Report.docx');M=json.loads((W/'document_manifest.json').read_text());Q=json.loads((W/'qa_results.json').read_text());src=(W/'manuscript.md').read_text()
norm=lambda s:re.sub(r'(?<=-)\s+(?=\w)', '', ' '.join(s.split()))
texts=[norm(p.get_text()) for p in pdf]
chapter_pages={}
for n in range(1,8):
 matches=[i+1 for i,t in enumerate(texts) if i>=12 and re.match(r'\d+ Chapter '+str(n)+r'\b',t)]
 assert len(matches)==1,(n,matches)
 chapter_pages[str(n)]={'pdf_page':matches[0],'printed_page':matches[0]-12}
romans=['i','ii','iii','iv','v','vi','vii','viii','ix','x','xi','xii']
footer_errors=[]
for i,p in enumerate(pdf):
 f=p.get_text(clip=fitz.Rect(0,780,p.rect.width,p.rect.height)).strip();wanted=romans[i] if i<12 else str(i-11)
 if f!=wanted:footer_errors.append([i+1,f,wanted])
assert not footer_errors,footer_errors
assert all(len(p.get_text('words'))>5 for p in pdf)
assert 40<=len(pdf)<=100
assert not Q['overflow'] and not any(Q['unresolved_tokens'].values())
assert not re.search(r'(?m)^#+ ', '\n'.join(p.get_text() for p in pdf))
body=' '.join(texts[12:chapter_pages['7']['pdf_page']-1]);cit=[]
for x in re.findall(r'\[(\d+)\]',body):
 if int(x) not in cit:cit.append(int(x))
assert cit==list(range(1,15)),cit
inventories={}
for typ,key,label in [('FIG','figures','Fig.'),('TABLE','tables','Table')]:
 rows=[]
 for k,v in M[key].items():
  ref='[[%s:%s]]'%('fig' if typ=='FIG' else 'tab',k)
  start=src.index('[['+typ+':'+k)
  assert ref in src[:start],k
  title=v.get('caption',v.get('title'));needle=norm(label+' '+v['num']+' '+title)
  pages=[i+1 for i,t in enumerate(texts) if i>=12 and needle in t]
  assert len(pages)==1,(k,pages)
  rows.append({'number':v['num'],'title':title,'pdf_page':pages[0],'printed_page':pages[0]-12})
 inventories[key]=rows
fields=Q['fields'];assert sum(x.strip().startswith('TOC ') for x in fields)==3
assert sum(x.strip().startswith('SEQ ') for x in fields)==38
assert len(D.tables)==28 and len(D.inline_shapes)==16
for t in D.tables:
 assert t.rows[0]._tr.find(qn('w:trPr')).find(qn('w:tblHeader')) is not None
 for row in t.rows:assert row._tr.find(qn('w:trPr')).find(qn('w:cantSplit')) is not None
# Check the tables and inline images remain within the text rectangle.
image_bounds=[]
for i,p in enumerate(pdf):
 for b in p.get_text('dict')['blocks']:
  if b['type']==1:
   x0,y0,x1,y1=b['bbox']
   if x0<104 or x1>526 or y0<70 or y1>772:image_bounds.append([i+1,b['bbox']])
assert not image_bounds,image_bounds
styles={}
for n in ['Normal','Front Text','Reference','Figure Caption','Table Caption','Heading 1','Heading 2','Heading 3']:
 s=D.styles[n];styles[n]={'font':s.font.name,'size_pt':s.font.size.pt if s.font.size else None,'line_spacing':s.paragraph_format.line_spacing}
assert styles['Normal']['font']=='Times New Roman' and styles['Normal']['size_pt']==12 and styles['Normal']['line_spacing']==1.5
assert all(styles[n]['line_spacing']==1 for n in styles if n not in ['Normal','Heading 1','Heading 2','Heading 3'])
assert all(styles[n]['font']=='Times New Roman' for n in styles)
out={'passed':True,'pages':len(pdf),'chapter_pages':chapter_pages,'footer_sequence_verified':True,'citation_order':cit,'inventories':inventories,'styles':styles,'docx_sha256':hashlib.sha256((R/'MLCN_Final_Mini_Project_Report.docx').read_bytes()).hexdigest(),'pdf_sha256':hashlib.sha256((R/'MLCN_Final_Mini_Project_Report.pdf').read_bytes()).hexdigest()}
(W/'final_checks.json').write_text(json.dumps(out,indent=2));print(f'PASS: {len(pdf)} pages, seven chapter starts, all footers, 38 numbered captions, 14 citations, image/text bounds and DOCX structures verified.')
for i in [0,1,2,4,12,23,24,32,50,53,63,70,71,73]:
 if i>=len(pdf):continue
 pix=pdf[i].get_pixmap(matrix=fitz.Matrix(1.4,1.4),alpha=False);pix.save(W/f'rendered/final_page_{i+1:02}.png')
