from pathlib import Path
from xml.sax.saxutils import escape
root=Path.cwd();w=root/'reports/workspace'
code='''Sub RenderReport
Dim props(0) As New com.sun.star.beans.PropertyValue
Dim saveProps(1) As New com.sun.star.beans.PropertyValue
Dim pdfProps(1) As New com.sun.star.beans.PropertyValue
Dim doc As Object, indexes As Object
Dim i As Integer, pass As Integer
props(0).Name = "Hidden"
props(0).Value = True
doc = StarDesktop.loadComponentFromURL("DOCURL", "_blank", 0, props())
For pass = 1 To 3
 doc.refresh()
 doc.TextFields.refresh()
 indexes = doc.getDocumentIndexes()
 For i = 0 To indexes.getCount() - 1
  indexes.getByIndex(i).update()
 Next i
Next pass
saveProps(0).Name = "FilterName"
saveProps(0).Value = "Office Open XML Text"
saveProps(1).Name = "Overwrite"
saveProps(1).Value = True
doc.storeAsURL("DOCURL", saveProps())
pdfProps(0).Name = "FilterName"
pdfProps(0).Value = "writer_pdf_Export"
pdfProps(1).Name = "Overwrite"
pdfProps(1).Value = True
doc.storeToURL("PDFURL", pdfProps())
doc.close(True)
StarDesktop.terminate()
End Sub
'''.replace('DOCURL',(root/'reports/MLCN_Final_Mini_Project_Report.docx').as_uri()).replace('PDFURL',(root/'reports/MLCN_Final_Mini_Project_Report.pdf').as_uri())
p=w/'lo_profile/user/basic/Standard/Module1.xba';p.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">'+escape(code)+'</script:module>')
(w/'render_macro.bas').write_text(code)
