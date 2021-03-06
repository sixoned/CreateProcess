unit CreateProcFunctions;

interface
uses
  Winapi.Windows, Vcl.Forms, ShellAPI;

procedure createProc(path : String);
procedure shellExProc(path : String; Sender: TForm);

implementation
///////////////////////////////createProc////////////////////////////////////
procedure createProc(path : String);
var
  Rlst: LongBool;
  StartUpInfo: TStartUpInfo;
  ProcessInfo: TProcessInformation;
  Error: integer;
begin
 FillChar(StartUpInfo, SizeOf(TStartUpInfo), 0);
  with StartUpInfo do
  begin
    cb := SizeOf(TStartUpInfo);
    dwFlags := STARTF_USESHOWWINDOW or STARTF_FORCEONFEEDBACK;
    wShowWindow := SW_SHOWNORMAL;
  end;
  Rlst := CreateProcess(PWideChar(path), nil, nil, nil, false, NORMAL_PRIORITY_CLASS, nil, nil, StartUpInfo, ProcessInfo);
  if Rlst then
  with ProcessInfo do begin
    WaitForInputIdle(hProcess, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
  end
else Error := GetLastError;
end;
///////////////////////////////shellExProc////////////////////////////////////
procedure shellExProc(path : String; Sender: TForm);
begin
   ShellExecute(Sender.Handle, 'open', PChar(path), nil, nil, SW_SHOWNORMAL);
end;
end.
