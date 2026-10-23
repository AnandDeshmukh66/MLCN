from pathlib import Path
import fitz,json,re
from PIL import Image,ImageOps,ImageDraw
from docx import Document
from docx.oxml.ns import qn
W=Path(__file__).parent; root=W.parent
pdf=fitz.open(root/'MLCN_Final_Mini_Project_Report.pdf')
texts=[p.get_text() for p in pdf]
(W/'rendered/report_text.txt').write_text('\n\n'.join(f'--- PDF PAGE {i+1} ---\n{t}' for i,t in enumerate(texts)))
info={'pages':len(pdf),'page_sizes':sorted(set((round(p.rect.width,2),round(p.rect.height,2)) for p in pdf)),'unresolved_tokens':{},'overflow':[],'page_info':[]}
for token in ['[[','[@','will be updated','Error!','Reference source not found']:
 info['unresolved_tokens'][token]=[i+1 for i,t in enumerate(texts) if token in t]
for i,p in enumerate(pdf):
 blocks=p.get_text('blocks'); lines=texts[i].strip().splitlines()
 info['page_info'].append({'pdf_page':i+1,'first':lines[:3],'last':lines[-2:],'words':len(p.get_text('words'))})
 for w in p.get_text('words'):
  if w[0]<99 or w[2]>p.rect.width-65 or w[1]<62 or w[3]>p.rect.height-25:info['overflow'].append([i+1,list(w[:5])])
for start in range(0,len(pdf),12):
 sheet=Image.new('RGB',(4*300,3*450),'#ddd');draw=ImageDraw.Draw(sheet)
 for j in range(start,min(start+12,len(pdf))):
  pix=pdf[j].get_pixmap(matrix=fitz.Matrix(.5,.5),alpha=False);im=Image.frombytes('RGB',[pix.width,pix.height],pix.samples);im.thumbnail((285,415))
  x=(j-start)%4*300;y=(j-start)//4*450;sheet.paste(im,(x+7,y+25));draw.text((x+10,y+5),str(j+1),fill='black')
 sheet.save(W/f'rendered/report_contact_{start+1:02}.jpg',quality=90)
doc=Document(root/'MLCN_Final_Mini_Project_Report.docx')
info['sections']=[{'width_cm':s.page_width.cm,'height_cm':s.page_height.cm,'left_cm':s.left_margin.cm,'right_cm':s.right_margin.cm,'top_cm':s.top_margin.cm,'bottom_cm':s.bottom_margin.cm,'numbering':dict(s._sectPr.find(qn('w:pgNumType')).attrib) if s._sectPr.find(qn('w:pgNumType')) is not None else None} for s in doc.sections]
info['tables']=len(doc.tables);info['figures']=len(doc.inline_shapes)
info['fields']=[x.text for x in doc.element.iter(qn('w:instrText'))]
info['normal_style']={'font':doc.styles['Normal'].font.name,'size':doc.styles['Normal'].font.size.pt,'line_spacing':doc.styles['Normal'].paragraph_format.line_spacing}
(W/'qa_results.json').write_text(json.dumps(info,indent=2))
print(json.dumps({k:v for k,v in info.items() if k!='page_info'},indent=2))
print('PAGE MAP')
for p in info['page_info']:print(p)
