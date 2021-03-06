unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TForm1 = class(TForm)
    pathTEdit: TEdit;
    OpenDialog1: TOpenDialog;
    runBtn: TButton;
    GroupBox1: TGroupBox;
    RadioButton1: TRadioButton;
    RadioButton2: TRadioButton;
    logMemo: TMemo;
    openBtn: TButton;
    procedure FormCreate(Sender: TObject);
    procedure openBtnClick(Sender: TObject);
    procedure runBtnClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  OpenDir : String;

implementation
uses
  TRegFunctions, strConsts, CreateProcFunctions;

{$R *.dfm}


///////////////////////////////FormCreate////////////////////////////////////
procedure TForm1.FormCreate(Sender: TObject);
begin
  if  (regKeyExists(LAST_PATH)) then begin
    pathTEdit.Text := regRead(LAST_PATH);
    OpenDir := pathTEdit.Text;
  end
  else
    begin
     openDialog1.InitialDir := DEFAULT_DIRECTORY;
    end;


end;
///////////////////////////////openBtnClick////////////////////////////////////
procedure TForm1.openBtnClick(Sender: TObject);
var
  pathText : String;
begin
  if (OpenDialog1.Execute()) then
    begin
      pathText := OpenDialog1.FileName;
      pathTEdit.Text := pathText;
      logMemo.Lines.Add(String.Format('Added new path: %s',[pathText]));
      OpenDir := pathTEdit.Text;
      regWrite(pathText);
    end;
end;
///////////////////////////////runBtnClick////////////////////////////////////
procedure TForm1.runBtnClick(Sender: TObject);
begin
  if (RadioButton1.Checked) then createProc(OpenDir)
  else
  begin
    shellExProc(OpenDir, Self);
  end;
end;

end.
