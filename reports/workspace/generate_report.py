import os,sys,re,json,collections
from pathlib import Path
from docx import Document
from docx.shared import Cm,Pt,RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH,WD_BREAK
from docx.enum.section import WD_SECTION_START
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from PIL import Image
from report_data import T,REFS,W,ROOT,A,E
D=Document();S=D.styles
for name in ['Normal','Body Text','Heading 1','Heading 2','Heading 3','Caption','Title','Subtitle','Footer']:
 s=S[name];s.font.name='Times New Roman';s.font.size=Pt(12);s.font.color.rgb=RGBColor(0,0,0);s._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'Times New Roman')
s=S['Normal'];s.paragraph_format.line_spacing=1.5;s.paragraph_format.space_after=Pt(19);s.paragraph_format.widow_control=True;s.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
for name in ['Heading 1','Heading 2','Heading 3']:
 s=S[name];s.font.bold=True;s.font.italic=False;s.font.size=Pt(16 if name=='Heading 1' else 12);s.paragraph_format.space_before=Pt(18);s.paragraph_format.space_after=Pt(12);s.paragraph_format.keep_with_next=True;s.paragraph_format.keep_together=True;s.paragraph_format.line_spacing=1.5
S['Heading 1'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.CENTER
S['Heading 2'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.LEFT
S['Heading 3'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.LEFT
for name,size in [('Front Heading',14),('Figure Caption',10),('Table Caption',11),('Table Body',10),('Reference',12),('Front Text',12),('List Entry',11)]:
 st=S.add_style(name,WD_STYLE_TYPE.PARAGRAPH);st.base_style=S['Normal'];st.font.name='Times New Roman';st.font.size=Pt(size);st.paragraph_format.line_spacing=1;st.paragraph_format.space_after=Pt(8);st.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.LEFT
S['Front Heading'].font.bold=True;S['Front Heading'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.CENTER;S['Front Heading'].paragraph_format.space_after=Pt(24);S['Front Heading'].paragraph_format.keep_with_next=True
S['Figure Caption'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.CENTER;S['Figure Caption'].paragraph_format.keep_together=True;S['Figure Caption'].paragraph_format.space_after=Pt(19)
S['Table Caption'].paragraph_format.keep_with_next=True;S['Table Caption'].font.bold=True;S['Table Caption'].paragraph_format.space_before=Pt(18)
S['Table Body'].paragraph_format.space_after=Pt(4);S['Table Body'].paragraph_format.space_before=Pt(4);S['Table Body'].paragraph_format.keep_with_next=False
S['Reference'].paragraph_format.space_after=Pt(12)
for n in range(1,4):
 nm=f'TOC {n}'
 if nm not in S:st=S.add_style(nm,WD_STYLE_TYPE.PARAGRAPH)
 else:st=S[nm]
 st.font.name='Times New Roman';st.font.size=Pt(11);st.paragraph_format.line_spacing=1;st.paragraph_format.space_after=Pt(4);st.paragraph_format.keep_with_next=False
sec=D.sections[0]
def section_setup(sec,fmt='lowerRoman',start=1):
 sec.page_width=Cm(21);sec.page_height=Cm(29.7);sec.top_margin=Cm(2.5);sec.bottom_margin=Cm(2.5);sec.left_margin=Cm(3.75);sec.right_margin=Cm(2.5);sec.header_distance=Cm(1.25);sec.footer_distance=Cm(1.25)
 el=sec._sectPr.find(qn('w:pgNumType'))
 if el is None:el=OxmlElement('w:pgNumType');sec._sectPr.append(el)
 el.set(qn('w:fmt'),fmt);el.set(qn('w:start'),str(start))
 sec.footer.is_linked_to_previous=False;p=sec.footer.paragraphs[0];p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.line_spacing=1;p.paragraph_format.space_after=Pt(0);field(p,'PAGE','i' if fmt=='lowerRoman' else '1')
def field(p,code,cache=''):
 r=p.add_run();e=OxmlElement('w:fldChar');e.set(qn('w:fldCharType'),'begin');r._r.append(e)
 r=p.add_run();e=OxmlElement('w:instrText');e.set(qn('xml:space'),'preserve');e.text=' '+code+' ';r._r.append(e)
 r=p.add_run();e=OxmlElement('w:fldChar');e.set(qn('w:fldCharType'),'separate');r._r.append(e)
 p.add_run(cache)
 r=p.add_run();e=OxmlElement('w:fldChar');e.set(qn('w:fldCharType'),'end');r._r.append(e)
section_setup(sec)
settings=D.settings.element;up=OxmlElement('w:updateFields');up.set(qn('w:val'),'true');settings.append(up)
# Explicitly avoid widow/orphan headings and split table rows.
def para(text='',style=None,align=None):
 p=D.add_paragraph(text,style=style)
 if align is not None:p.alignment=align
 return p
def centered(text,size=12,bold=False,italic=False,after=10,before=0):
 p=para('', 'Front Text',WD_ALIGN_PARAGRAPH.CENTER);p.paragraph_format.space_after=Pt(after);p.paragraph_format.space_before=Pt(before);r=p.add_run(text);r.bold=bold;r.italic=italic;r.font.size=Pt(size);return p
front_titles=[]
def front(title,break_before=True):
 if break_before:D.add_page_break()
 p=para(title,'Front Heading');front_titles.append(title);return p
def table_raw(heads,rows,widths=None,size=10):
 t=D.add_table(rows=1,cols=len(heads));t.style='Table Grid';t.autofit=False;t.alignment=WD_TABLE_ALIGNMENT.CENTER
 if widths is None:widths=[14.75/len(heads)]*len(heads)
 for col,w in zip(t.columns,widths):col.width=Cm(w)
 for i,h in enumerate(heads):t.rows[0].cells[i].text=str(h)
 for row in rows:
  cells=t.add_row().cells
  for i,x in enumerate(row):cells[i].text=str(x)
 for j,row in enumerate(t.rows):
  trpr=row._tr.get_or_add_trPr();cs=OxmlElement('w:cantSplit');trpr.append(cs)
  if j==0:
   repeat=OxmlElement('w:tblHeader');trpr.append(repeat)
  for i,cell in enumerate(row.cells):
   cell.width=Cm(widths[i])
   if j==0:
    sh=OxmlElement('w:shd');sh.set(qn('w:fill'),'E8EEF3');cell._tc.get_or_add_tcPr().append(sh)
   for p in cell.paragraphs:
    p.style=S['Table Body']
    for r in p.runs:r.font.size=Pt(size);r.font.bold=j==0
 return t
TITLE='MLCN: MACHINE LEARNING CYBERSECURITY NETWORK'
centered(TITLE,16,True,after=16)
centered('This project report is submitted to',12,True,True,after=4)
centered('Yeshwantrao Chavan College of Engineering',12,True,after=4)
centered('(An Autonomous Institution Affiliated to Rashtrasant Tukdoji Maharaj Nagpur University)',10,italic=True,after=14)
centered('In partial fulfillment of the\nrequirement For the award of the\ndegree',12,True,True,after=48)
centered('Of',12,True,True,after=10)
centered('Bachelor of Technology in [BRANCH]',14,True,after=10)
centered('By',12,True,True,after=10)
centered('[STUDENT NAME(S) AND ROLL NUMBER(S)]',14,True,after=14)
centered('Under the guidance of',12,True,True,after=24)
centered('[GUIDE NAME]',12,True,after=12)
p=para('', 'Front Text',WD_ALIGN_PARAGRAPH.CENTER);p.add_run().add_picture(str(W/'figures/institution_logo.jpeg'),height=Cm(1.6));p.paragraph_format.space_after=Pt(6)
centered('DEPARTMENT OF [DEPARTMENT]',14,True,after=12)
centered('Nagar Yuwak Shikshan Sanstha’s',12,after=4)
centered('YESHWANTRAO CHAVAN COLLEGE OF ENGINEERING,',14,True,after=4)
centered('(An autonomous institution affiliated to Rashtrasant Tukadoji Maharaj Nagpur University, Nagpur)',9,after=4)
centered('NAGPUR – 441 110',14,True,after=8)
centered('2025–26',14,True,after=0)
# Add title to contents via TC; no extra visible heading.
field(D.paragraphs[0],'TC "Title Page" \\f P \\l 1','')
front('CERTIFICATE OF APPROVAL')
p=para('Certified that the project report entitled “'+TITLE+'” has been successfully completed by [NAME OF THE STUDENT(S)] under the guidance of [NAME OF GUIDE] in recognition to the partial fulfillment for the award of the degree of Bachelor of Technology in [BRANCH], Yeshwantrao Chavan College of Engineering (An Autonomous Institution Affiliated to Rashtrasant Tukdoji Maharaj Nagpur University)','Front Text');p.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY;p.paragraph_format.space_before=Pt(30);p.paragraph_format.space_after=Pt(90)
a,b=p.text.split('Yeshwantrao Chavan College of Engineering',1);p.clear();p.add_run(a);p.add_run('Yeshwantrao Chavan College of Engineering').bold=True;r=p.add_run(b);r.bold=True;r.italic=True
t=table_raw(['Signature','Signature','Signature','Signature'],[['[Name of Guide]\n(Guide)','[Name of Co-Guide]\n(Co-Guide)','[Name of Co-ordinator]\n(Coordinator)','[Name of Head of deptt]\n(HoD)']],size=10)
# Borderless signature positions reproduce the institutional sample.
def signature_layout(t):
 for c in t._tbl.iter(qn('w:tc')):
  pr=c.find(qn('w:tcPr'))
  for sh in list(pr.findall(qn('w:shd'))):pr.remove(sh)
  bor=OxmlElement('w:tcBorders')
  for edge in ['top','left','bottom','right']:
   el=OxmlElement('w:'+edge);el.set(qn('w:val'),'nil');bor.append(el)
  pr.append(bor)
 for row in t.rows:
  for cell in row.cells:
   for p in cell.paragraphs:
    p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    for r in p.runs:r.font.size=Pt(12);r.bold=False
signature_layout(t)
para('Unsigned approval template. Certification requires verification and signatures by the authorized faculty.','Front Text').paragraph_format.space_before=Pt(36)
front('DECLARATION')
para('I / we certify that','Front Text')
for s in ['a.  The work contained in this project has been done by me under the guidance of my supervisor(s).','b.  The work has not been submitted to any other Institute for any degree or diploma.','c.  I have followed the guidelines provided by the Institute in preparing the project report.','d.  I have conformed to the norms and guidelines given in the Ethical Code of Conduct of the Institute.','e.  Whenever I have used materials (data, theoretical analysis, figures, and text) from other sources, I have given due credit to them by citing them in the text of the report and giving their details in the references. Further, I have taken permission from the copyright owners of the sources, whenever necessary.']:
 p=para(s,'Front Text');p.paragraph_format.space_after=Pt(16);p.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
p=para('Signature of the Student/s: [TO BE SIGNED]','Front Text',WD_ALIGN_PARAGRAPH.RIGHT);p.paragraph_format.space_before=Pt(24)
t=table_raw(['Name of the student','Signature of the Student','Name of the student','Signature of the Student'],[[f'{i}. [NAME]','[SIGNATURE]',f'{i+3}. [NAME]','[SIGNATURE]'] for i in range(1,4)],size=10)
signature_layout(t)
para('Unsigned declaration template for student verification. Unused student positions may be removed.','Front Text').paragraph_format.space_before=Pt(12)
front('ACKNOWLEDGEMENT')
para('The project team acknowledges the institutional framework provided by Yeshwantrao Chavan College of Engineering for the mini-project. This report documents the MLCN implementation and its technical evidence for review by the department and guide.','Front Text')
para('[STUDENT INPUT REQUIRED: identify the guide, co-guide, department, laboratory staff and any individuals who actually assisted the project. Describe the nature of their contribution and confirm permission to name them.]','Front Text')
para('The report recognizes the publicly documented contributions of the dataset providers and the research cited in the bibliography. The implementation uses open-source software including Scapy, XGBoost, NumPy and Streamlit. Original technical diagrams and evidence-based charts are prepared for this report.','Front Text')
para('[STUDENT INPUT REQUIRED: record any verified funding, external assistance or institutional disclosure required for document-generation support. No sponsorship or collaboration is asserted here.]','Front Text')
front('TABLE OF CONTENTS')
p=para('', 'List Entry');field(p,'TOC \\o "1-2" \\t "Front Heading,1" \\f P \\h \\z','Contents will be updated during rendering.')
front('LIST OF TABLES');p=para('', 'List Entry');field(p,'TOC \\t "Table Caption,1" \\h \\z','Table list will be updated during rendering.')
front('LIST OF FIGURES');p=para('', 'List Entry');field(p,'TOC \\t "Figure Caption,1" \\h \\z','Figure list will be updated during rendering.')
front('LIST OF ABBREVIATIONS')
abbr=[('AP','Average precision'),('API','Application programming interface'),('BPF','Berkeley Packet Filter'),('CIC','Canadian Institute for Cybersecurity'),('CLI','Command-line interface'),('CO / PO','Course outcome / program outcome'),('CSV','Comma-separated values'),('DDoS / DoS','Distributed denial of service / denial of service'),('FIN / SYN / RST','Finish / synchronize / reset TCP control flags'),('FP / FN / TP','False positive / false negative / true positive'),('HTTP','Hypertext Transfer Protocol'),('IAT','Inter-arrival time'),('ICMP','Internet Control Message Protocol'),('IDS','Intrusion detection system'),('IP','Internet Protocol'),('JSON / JSONL','JavaScript Object Notation / JSON Lines'),('LIME','Local Interpretable Model-agnostic Explanations'),('LLM','Large language model'),('MLCN','Machine Learning Cybersecurity Network'),('PR / ROC','Precision–recall / receiver operating characteristic'),('ROC-AUC','Area under the receiver operating characteristic curve'),('SHA-256','Secure Hash Algorithm, 256-bit digest'),('SHAP','SHapley Additive exPlanations'),('TCP / UDP','Transmission Control Protocol / User Datagram Protocol'),('UTC','Coordinated Universal Time'),('XAI','Explainable artificial intelligence')]
table_raw(['Abbreviation','Expansion'],abbr,[3.0,11.75],size=10)
front('LIST OF SYMBOLS / NOMENCLATURE')
table_raw(['Symbol','Meaning / unit'],[('D','Flow duration, microseconds'),('gᵢ','Consecutive inter-arrival gap, microseconds'),('m','Number of values in a statistical series'),('n','Total packets in a completed flow'),('n_b','Backward packet count'),('n_f','Forward packet count'),('pₖ','Model probability for class k'),('s','Sample standard deviation in the stated feature unit'),('tᵢ','Timestamp of packet i, integer microseconds'),('xⱼ','Value of model feature j'),('μ','Arithmetic mean'),('µs','Microseconds (10⁻⁶ seconds)')],[3,11.75],size=11)
para('Symbols are arranged by Latin letters followed by Greek letters. Subscripts indicate packet, feature, class or direction indices. Named code objects and literal feature names retain their repository spelling.','Front Text')
front('ABSTRACT')
abstract='Network intrusion detection requires a consistent transformation from observed packets to the numerical representation used by a trained classifier. This project investigates Machine Learning Cybersecurity Network (MLCN), a laboratory platform connecting packet capture, parsing, bidirectional flow construction, 24-feature extraction and five-class XGBoost inference. The current repository, training notebook, model artifacts and validation logs are audited, and all 251,812 saved test predictions are independently replayed. Offline accuracy is 99.4238%, balanced accuracy is 99.5568%, and macro F1 is 0.93358. Brute Force precision remains limited to 53.1378%, with 799 false positives. Current code corrects the historical timing-unit mismatch by using microsecond timing features and per-second rates. Saved laboratory records provide narrower evidence of selected-profile recognition and are separated from synthetic demonstration output. Six of 202 executed tests fail in demonstration labelling or presentation behavior. A Gemini-based explanation workflow is proposed with explicit evidence, privacy and uncertainty controls; it is not implemented. The findings support a connected research prototype while identifying reproducibility, provenance and live-validation requirements before broader deployment.'
para(abstract,'Front Text').paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
front('PROJECT CO–PO MATRIX')
para('Course outcome (CO) and program outcome (PO) mappings require approval from the department. The placeholders below do not assert any achieved mapping or correlation level. Replace the row labels, number of outcomes and every pending cell with the institution-approved values.','Front Text')
table_raw(['CO']+[f'PO{i}' for i in range(1,13)],[[f'[CO {i}]']+['—']*12 for i in range(1,5)],[1.55]+[1.1]*12,size=8)
para('Legend: — = mapping pending, not zero and not “no correlation”. No numerical strength scale is assigned without the approved institutional rubric.','Front Text').paragraph_format.space_before=Pt(14)
para('[REQUIRED INPUT: official course outcomes, program outcomes, approved matrix, correlation scale, evaluator and approval date.]','Front Text')
para('Suggested evidence for departmental review includes modular implementation, experimental analysis, reproducibility, technical documentation and responsible interpretation of model output. These are project activities, not approved CO–PO assignments.','Front Text')
# Map figures, tables and citations in first-appearance order before rendering.
source=(W/'manuscript.md').read_text();source=re.sub(r'(?m)^(#{1,3}[^\n]+)\n',r'\n\n\1\n\n',source);figmap={};tabmap={};chap=0;fc=collections.Counter();tc=collections.Counter();citation=[]
for line in source.splitlines():
 m=re.match(r'# (\d+) ',line)
 if m:chap=int(m[1])
 m=re.match(r'\[\[FIG:([^|]+)\|(.+)\]\]',line)
 if m:fc[chap]+=1;figmap[m[1]]={'num':f'{chap}.{fc[chap]}','caption':m[2],'chapter':chap,'index':fc[chap]}
 m=re.match(r'\[\[TABLE:([^]]+)\]\]',line)
 if m:
  key=m[1]
  if key=='publications':num='P.1';ch='P';idx=1
  else:tc[chap]+=1;num=f'{chap}.{tc[chap]}';ch=chap;idx=tc[chap]
  tabmap[key]={'num':num,'chapter':ch,'index':idx,**T[key]}
for k in re.findall(r'\[@([^]]+)\]',source):
 if k not in citation:citation.append(k)
nums={k:i+1 for i,k in enumerate(citation)}
def replace(text):
 text=re.sub(r'\[@([^]]+)\]',lambda m:'['+str(nums[m[1]])+']',text)
 text=re.sub(r'\[\[fig:([^]]+)\]\]',lambda m:figmap[m[1]]['num'],text)
 text=re.sub(r'\[\[tab:([^]]+)\]\]',lambda m:tabmap[m[1]]['num'],text)
 return text
sec=D.add_section(WD_SECTION_START.NEW_PAGE);section_setup(sec,'decimal',1)
first=True
for block in source.split('\n\n'):
 block=block.strip()
 if not block:continue
 if block.startswith('# '):
  m=re.match(r'# (\d+) (.*)',block);p=para(f'Chapter {m[1]}\n{m[2]}','Heading 1');p.paragraph_format.page_break_before=not first;first=False
 elif block.startswith('#P '):para(block[3:],'Heading 1').paragraph_format.page_break_before=True
 elif block.startswith('### '):para(block[4:],'Heading 3')
 elif block.startswith('## '):para(block[3:],'Heading 2')
 elif block.startswith('[[FIG:'):
  key=block[6:].split('|')[0];item=figmap[key]
  p=para('');p.alignment=WD_ALIGN_PARAGRAPH.LEFT;p.paragraph_format.left_indent=Cm(0.05);p.paragraph_format.line_spacing=1;p.paragraph_format.space_before=Pt(18);p.paragraph_format.space_after=Pt(6);p.paragraph_format.keep_with_next=True
  p.add_run().add_picture(str(W/'figures'/f'{key}.png'),width=Cm(14.1))
  p=para('', 'Figure Caption');p.add_run('Fig. '+str(item['chapter'])+'.');field(p,'SEQ Fig'+str(item['chapter'])+' \\* ARABIC',str(item['index']));p.add_run(' '+item['caption'])
 elif block.startswith('[[TABLE:'):
  key=block[8:-2];item=tabmap[key];p=para('', 'Table Caption');p.add_run('Table '+str(item['chapter'])+'.');field(p,'SEQ Tab'+str(item['chapter'])+' \\* ARABIC',str(item['index']));p.add_run(' '+item['title'])
  rows=[[replace(str(x)) for x in row] for row in item['rows']];t=table_raw(item['heads'],rows,item['widths'],size=9 if key in ['hashes','failures','modules','publications'] else 10)
  if key=='hashes':
   for row in t.rows[1:]:
    p=row.cells[1].paragraphs[0];s=p.text;p.text=s[:32]+'\n'+s[32:];p.style=S['Table Body']
    for r in p.runs:r.font.size=Pt(9)
  para('').paragraph_format.space_after=Pt(0)
 elif block=='[[REFERENCES]]':
  for key in citation:
   txt,url=REFS[key];p=para(f'[{nums[key]}] '+txt+' Available: '+url,'Reference');p.paragraph_format.keep_together=True
   if key=='pr':
    text=p.text;p.clear();before,after=text.split('vol. 10',1);p.add_run(before+'vol. ');p.add_run('10').underline=True;p.add_run(after)
 else:para(replace(block.replace('\n',' ')))
# Keep the title in the preliminary contents without changing its visual layout.
D.core_properties.title=TITLE;D.core_properties.subject='B.Tech. Mini Project Report — verified repository investigation';D.core_properties.author='[STUDENT NAME(S)]';D.core_properties.keywords='MLCN, YCCE, IDS, XGBoost, mini project'
# Theme font attributes can override an explicit font during compatible rendering.
for st in S:
 if hasattr(st,'font') and st.font.name=='Times New Roman':
  rf=st._element.get_or_add_rPr().rFonts
  for attr in list(rf.attrib):
   if 'theme' in attr.lower():del rf.attrib[attr]
  for attr in ['ascii','hAnsi','eastAsia','cs']:rf.set(qn('w:'+attr),'Times New Roman')
path=ROOT/'reports/MLCN_Final_Mini_Project_Report.docx';D.save(path)
manifest={'figures':figmap,'tables':{k:{'num':v['num'],'title':v['title'],'rows':len(v['rows'])} for k,v in tabmap.items()},'citations':[{ 'number':nums[k],'key':k,'text':REFS[k][0],'url':REFS[k][1]} for k in citation],'abstract_words':len(abstract.split()),'body_words':len(source.split()),'paragraphs':len(D.paragraphs),'tables_count':len(D.tables)}
(W/'document_manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps({k:v for k,v in manifest.items() if k not in ['figures','tables','citations']}));print(path)
