unit TRegFunctions;

interface
  uses
  Windows;
  procedure regWrite(writeDir:String);
  function  regRead(readKey : String) : String;
  function  regKeyExists(checkingKey : String) : Boolean;

implementation
  uses
  Registry, strConsts;
///////////////////////////////regWrite////////////////////////////////////
  procedure regWrite(writeDir : String);
  var
    writeRegPath : TRegistry;
  begin
    writeRegPath := TRegistry.Create();
      try
        writeRegPath.RootKey := HKEY_CURRENT_USER;
        writeRegPath.OpenKey(OPEN_KEY_VALUE, true);
        writeRegPath.WriteString(LAST_PATH, writeDir);
      finally
        writeRegPath.Free;
      end;
  end;
///////////////////////////////regRead////////////////////////////////////
  function  regRead(readKey : String) : String;
  var
    readRegPath : TRegistry;
    readPath    : String;
  begin
    readRegPath := TRegistry.Create();
      try
        readRegPath.RootKey := HKEY_CURRENT_USER;
        readRegPath.OpenKey(OPEN_KEY_VALUE, true);
        readPath := readRegPath.ReadString(readKey);
        Result := readPath;
      finally
        readRegPath.Free();
      end;
  end;
///////////////////////////////regKeyExists////////////////////////////////////
function  regKeyExists(checkingKey : String) : Boolean;
var
    checkKey : TRegistry;

  begin
    checkKey := TRegistry.Create();
      try
        checkKey.RootKey := HKEY_CURRENT_USER;
        checkKey.OpenKey(OPEN_KEY_VALUE, true);
        Result := checkKey.ValueExists(checkingKey)
      finally
        checkKey.Free();
      end;
  end;
end.
