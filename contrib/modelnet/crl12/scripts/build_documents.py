from pathlib import Path
import re,json,textwrap
from docx import Document
from docx.shared import Inches,Pt,RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT,WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from markdown_it import MarkdownIt
R=Path(__file__).resolve().parents[1]
md=MarkdownIt('commonmark',{'html':True}).enable('table')
FONT='Inter'
MONO='DejaVu Sans Mono'
INK='172330';MUTED='5B6878';ACCENT='23445E'

def shade(element,fill):
 if hasattr(element,'_tc'):pr=element._tc.get_or_add_tcPr()
 else:pr=element._p.get_or_add_pPr()
 x=OxmlElement('w:shd');x.set(qn('w:fill'),fill);pr.append(x)
def hyperlink(p,label,target,internal=False):
 h=OxmlElement('w:hyperlink')
 if internal:h.set(qn('w:anchor'),target)
 else:h.set(qn('r:id'),p.part.relate_to(target,'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink',is_external=True))
 r=OxmlElement('w:r');pr=OxmlElement('w:rPr');f=OxmlElement('w:rFonts');f.set(qn('w:ascii'),FONT);f.set(qn('w:hAnsi'),FONT);pr.append(f)
 c=OxmlElement('w:color');c.set(qn('w:val'),ACCENT);pr.append(c);r.append(pr);t=OxmlElement('w:t');t.text=label;r.append(t);h.append(r);p._p.append(h)
def bookmark(p,name,n):
 a=OxmlElement('w:bookmarkStart');a.set(qn('w:id'),str(n));a.set(qn('w:name'),name)
 b=OxmlElement('w:bookmarkEnd');b.set(qn('w:id'),str(n));p._p.insert(0,a);p._p.append(b)
def inline(p,tokens,current_md):
 bold=italic=False;i=0
 while i<len(tokens):
  t=tokens[i]
  if t.type=='strong_open':bold=True
  elif t.type=='strong_close':bold=False
  elif t.type=='em_open':italic=True
  elif t.type=='em_close':italic=False
  elif t.type=='link_open':
   href=t.attrGet('href');i+=1;label=''
   while i<len(tokens) and tokens[i].type!='link_close':label+=tokens[i].content;i+=1
   hyperlink(p,label,href)
  elif t.type in ('text','code_inline'):
   r=p.add_run(t.content);r.bold=bold;r.italic=italic
   if t.type=='code_inline':r.font.name=MONO;r.font.size=Pt(8)
  elif t.type in ('softbreak','hardbreak'):p.add_run('\n' if t.type=='hardbreak' else ' ')
  elif t.type=='image':
   path=(current_md.parent/t.attrGet('src')).resolve()
   if not path.exists():raise FileNotFoundError(path)
   pic=p.add_run().add_picture(str(path),width=Inches(6.55))
   dp=pic._inline.docPr;dp.set('descr',t.content)
   p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.keep_with_next=True
  i+=1

def configure(doc,title):
 sec=doc.sections[0];sec.page_width=Inches(8.27);sec.page_height=Inches(11.69)
 sec.top_margin=Inches(.70);sec.bottom_margin=Inches(.70);sec.left_margin=Inches(.80);sec.right_margin=Inches(.80)
 sec.header_distance=Inches(.28);sec.footer_distance=Inches(.28);sec.different_first_page_header_footer=True
 for name in ['Normal','Body Text']:
  s=doc.styles[name];s.font.name=FONT;s.font.size=Pt(10.2);s.font.color.rgb=RGBColor.from_string(INK)
  s.paragraph_format.line_spacing=1.13;s.paragraph_format.space_after=Pt(7)
  s.paragraph_format.widow_control=True
 for name,size in [('Title',30),('Subtitle',16),('Heading 1',18),('Heading 2',13),('Heading 3',11)]:
  s=doc.styles[name];s.font.name=FONT;s.font.size=Pt(size);s.font.bold=name!='Subtitle';s.font.color.rgb=RGBColor.from_string(INK)
  s.paragraph_format.keep_with_next=True;s.paragraph_format.space_before=Pt(16 if name.startswith('Heading') else 8);s.paragraph_format.space_after=Pt(7)
 c=doc.styles['Caption'];c.font.name=FONT;c.font.size=Pt(8.4);c.font.color.rgb=RGBColor.from_string(MUTED);c.paragraph_format.line_spacing=1.10
 h=sec.header.paragraphs[0];h.text='BTX  /  THE COGNITIVE RESERVE LAYER';h.runs[0].font.name=FONT;h.runs[0].font.size=Pt(7.5);h.runs[0].font.color.rgb=RGBColor.from_string(MUTED)
 f=sec.footer.paragraphs[0];f.alignment=WD_ALIGN_PARAGRAPH.RIGHT;r=f.add_run('FRAMEWORK v1.2  ·  ');r.font.name=FONT;r.font.size=Pt(7.5);r.font.color.rgb=RGBColor.from_string(MUTED)
 fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');f._p.append(fld)
 doc.core_properties.title=title;doc.core_properties.subject='BTX Cognitive Reserve Layer: strategy and neutral institutional integration';doc.core_properties.author='Prepared for BTX';doc.core_properties.version='1.2'
 # Make automatic hyphenation optional; explicit keep-together is limited to headings/tables.
 settings=doc.settings.element;lang=OxmlElement('w:themeFontLang');lang.set(qn('w:val'),'en-US');settings.append(lang)

reports=[]
for current in sorted((R/'docs').glob('*.md')):
 text=current.read_text();tokens=md.parse(text);doc=Document()
 title=text.splitlines()[0].lstrip('# ');configure(doc,title)
 # Extract consecutive opening headings as cover, then body begins at metadata.
 cover=[];i=0
 while i<len(tokens) and tokens[i].type=='heading_open' and len(cover)<3:
  cover.append((int(tokens[i].tag[1:]),tokens[i+1].content));i+=3
 p=doc.add_paragraph();p.paragraph_format.space_before=Pt(58);r=p.add_run('BTX  /  STRATEGY & IMPLEMENTATION');r.font.name=FONT;r.font.size=Pt(9);r.bold=True;r.font.color.rgb=RGBColor.from_string(MUTED)
 for level,content in cover:doc.add_paragraph(content,'Title' if level==1 else 'Subtitle')
 p=doc.add_paragraph('Framework v1.2\n17 September 2026');p.paragraph_format.space_before=Pt(24)
 p=doc.add_paragraph('Financial reserves. Productive capability.\nOne neutral interoperability layer.');p.paragraph_format.space_before=Pt(44);p.runs[0].font.size=Pt(16);p.runs[0].font.color.rgb=RGBColor.from_string(ACCENT)
 # Static clickable contents, with exact in-document bookmarks.
 headings=[]
 for n in range(i,len(tokens)-1):
  if tokens[n].type=='heading_open' and tokens[n].tag=='h1':headings.append((n,tokens[n+1].content))
 doc.add_page_break();doc.add_paragraph('Contents','Heading 1')
 heading_anchors={n:'crl_section_'+str(k+1) for k,(n,_) in enumerate(headings)}
 for n,label in headings:
  p=doc.add_paragraph();p.paragraph_format.space_after=Pt(4);p.paragraph_format.line_spacing=1.03
  hyperlink(p,label,heading_anchors[n],True)
 doc.add_page_break()
 quote=False;listlevel=0
 while i<len(tokens):
  t=tokens[i]
  if t.type=='heading_open':
   level=min(int(t.tag[1:]),3);p=doc.add_paragraph(style='Heading '+str(level));inline(p,tokens[i+1].children or [],current)
   if i in heading_anchors:bookmark(p,heading_anchors[i],i+1)
   if current.name.startswith('06_') and level==2:
    p.paragraph_format.space_before=Pt(12);p.runs[0].font.size=Pt(11.4)
   i+=3;continue
  if t.type=='paragraph_open':
   content=tokens[i+1];p=doc.add_paragraph()
   if listlevel:p.paragraph_format.left_indent=Inches(.18*listlevel);p.add_run('• ')
   inline(p,content.children or [],current)
   if quote:
    p.paragraph_format.left_indent=Inches(.16);p.paragraph_format.right_indent=Inches(.08);p.paragraph_format.space_before=Pt(6);p.paragraph_format.space_after=Pt(12)
    for r in p.runs:r.font.color.rgb=RGBColor.from_string(ACCENT)
   if content.content.startswith(('*Figure','**Figure')) or (len(content.children or [])==1 and content.children[0].type=='image'):
    if not any(c.type=='image' for c in (content.children or [])):p.style='Caption'
   i+=3;continue
  if t.type=='blockquote_open':quote=True
  elif t.type=='blockquote_close':quote=False
  elif t.type in ('bullet_list_open','ordered_list_open'):listlevel+=1
  elif t.type in ('bullet_list_close','ordered_list_close'):listlevel=max(0,listlevel-1)
  elif t.type in ('fence','code_block'):
   p=doc.add_paragraph();p.paragraph_format.line_spacing=1.05;p.paragraph_format.space_before=Pt(4);p.paragraph_format.space_after=Pt(10)
   p.paragraph_format.keep_together=True
   p.paragraph_format.left_indent=Inches(.1);p.paragraph_format.right_indent=Inches(.06);shade(p,'F3F5F7')
   lines=[]
   for l in t.content.rstrip().splitlines():lines.extend(textwrap.wrap(l,96,replace_whitespace=False,drop_whitespace=False) or [''])
   for j,l in enumerate(lines):
    if j:p.add_run('\n')
    r=p.add_run(l);r.font.name=MONO;r.font.size=Pt(8)
  elif t.type=='table_open':
   rows=[];row=[];i+=1
   while i<len(tokens) and tokens[i].type!='table_close':
    z=tokens[i]
    if z.type=='tr_open':row=[]
    elif z.type in ('th_open','td_open'):row.append(tokens[i+1].children or []);i+=1
    elif z.type=='tr_close':rows.append(row)
    i+=1
   if rows:
    cols=max(map(len,rows));widths=[6.67/cols]*cols
    if cols==3:widths=[1.60,2.55,2.52]
    if cols==4:widths=[1.35,1.85,1.8,1.67]
    table=doc.add_table(rows=0,cols=cols);table.alignment=WD_TABLE_ALIGNMENT.CENTER;table.autofit=False
    for col,w in zip(table.columns,widths):col.width=Inches(w)
    for ri,cellsdata in enumerate(rows):
     rowobj=table.add_row();trpr=rowobj._tr.get_or_add_trPr();x=OxmlElement('w:cantSplit');trpr.append(x)
     if ri==0:x=OxmlElement('w:tblHeader');trpr.append(x)
     for ci,child in enumerate(cellsdata):
      c=rowobj.cells[ci];c.width=Inches(widths[ci]);c.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.TOP;p=c.paragraphs[0]
      p.paragraph_format.space_before=Pt(6);p.paragraph_format.space_after=Pt(6);p.paragraph_format.line_spacing=1.08
      inline(p,child,current)
      for r in p.runs:r.font.size=Pt(8.8);r.bold=ri==0 or r.bold
      shade(c,'EAF0F4' if ri==0 else 'F8FAFB' if ri%2==0 else 'FFFFFF')
    p=doc.add_paragraph();p.paragraph_format.space_after=Pt(2);p.paragraph_format.space_before=Pt(0)
  i+=1
 out=current.with_suffix('.docx');doc.save(out)
 reports.append({'file':out.name,'words':len(text.split()),'markdown':current.name})
(R/'qa/document-build.json').write_text(json.dumps(reports,indent=2));print(json.dumps(reports,indent=2))
