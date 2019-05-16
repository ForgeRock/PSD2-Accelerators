If Not WScript.Arguments.Named.Exists("elevate") Then
  CreateObject("Shell.Application").ShellExecute WScript.FullName _
    , """" & WScript.ScriptFullName & """ /elevate", "", "runas", 1
  WScript.Quit
End If

IPAddress = "35.204.122.163"
HostFileRecord = IPAddress & " obie-rcs-mocks.psd2acceldemo.fridam.aeet-forgerock.com"

Const ForReading = 1, ForWriting = 2, ForAppending = 8, ReadOnly = 1
Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")
WinDir = WshShell.ExpandEnvironmentStrings("%WinDir%")

HostsFile = WinDir & "\System32\Drivers\etc\Hosts"

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objTS = objFSO.OpenTextFile(HostsFile, ForReading)
strContents = objTS.ReadAll
objTS.Close

arrLines = Split(strContents, vbNewLine)
Set objTS = objFSO.OpenTextFile(HostsFile, ForWriting)

Found = false
For Each strLine In arrLines
	If InStr (strLine, IPAddress) <> 0 Then		
		objTS.WriteLine HostFileRecord
		Found = true
	Else
		objTS.WriteLine strLine
	End If
Next

If Not Found Then
	objTS.WriteLine HostFileRecord
End If

objTS.Close
WScript.quit