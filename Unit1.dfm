object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Form1'
  ClientHeight = 236
  ClientWidth = 511
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object pathTEdit: TEdit
    Left = 20
    Top = 18
    Width = 399
    Height = 21
    ReadOnly = True
    TabOrder = 0
  end
  object runBtn: TButton
    Left = 20
    Top = 57
    Width = 75
    Height = 27
    Caption = 'Run'
    TabOrder = 1
    OnClick = runBtnClick
  end
  object GroupBox1: TGroupBox
    Left = 107
    Top = 57
    Width = 121
    Height = 63
    Caption = ' Execution method '
    TabOrder = 2
    object RadioButton1: TRadioButton
      Left = 10
      Top = 16
      Width = 113
      Height = 17
      Caption = 'CreateProcess'
      Checked = True
      TabOrder = 0
      TabStop = True
    end
    object RadioButton2: TRadioButton
      Left = 10
      Top = 39
      Width = 113
      Height = 17
      Caption = 'ShellExecute'
      TabOrder = 1
    end
  end
  object logMemo: TMemo
    Left = 0
    Top = 160
    Width = 511
    Height = 76
    Align = alBottom
    TabOrder = 3
  end
  object openBtn: TButton
    Left = 425
    Top = 18
    Width = 75
    Height = 21
    Caption = 'Open'
    TabOrder = 4
    OnClick = openBtnClick
  end
  object OpenDialog1: TOpenDialog
    Left = 416
    Top = 54
  end
end
