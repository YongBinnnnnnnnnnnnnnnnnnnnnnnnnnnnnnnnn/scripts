Dim title, text
If WScript.Arguments.Count = 2 Then
  title = WScript.Arguments.item(0)
  text = WScript.Arguments.item(1)
Else
  title = InputBox("title:", "")
  text = InputBox("text:", "")
End If

text = Replace(text , "\n", vbNewLine)

MsgBox text, vbinformation +vbSystemModal, title