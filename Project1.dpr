program Project1;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  TRegFunctions in 'TRegFunctions.pas',
  strConsts in 'strConsts.pas',
  CreateProcFunctions in 'CreateProcFunctions.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
