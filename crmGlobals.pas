// ********************************************************* //
// Project CARMA 2016-2018                                   *
// Arthur Silaev Bryansk Russia                              *
// Corp: rivc7_SilaevAV@msk.rzd @ Public:veloforge@gmail.com *
// Administrative tool for Windows systems                   *
// Global variables and functions                            *
// ********************************************************* //

unit crmGlobals;

interface
{$INCLUDE carma.inc}
 uses
  SysUtils, Classes, Forms, Messages, Windows, Cnst.Strings, Utils.Sys, dbConventions,
  inifiles {$IFDEF DEBUG_VER}, Obj.ScanDebug {$ENDIF}, Utils.Ip;

const
  MESSENGER_DEBUG_LOCAL_MACHINE = false;

  LOCALE_RUSSIAN  = 0;
  LOCALE_ENGLISH  = 1;

  APP_NAME        = 'CARMA';
  SPREAD_LOG_MSGDLL = 'crmdiag.dll';
  SPREAD_LOG_FILE   = 'carma.evt';

  LPROFILE_ALWAYS   = 0;
  LPROFILE_ON_SCAN  = 1;
  LPROFILE_ON_NEVER = 2;

  WAIT_SIGNAL_ALL_DIED   = MaxInt;

  MAX_WAIT_PER_COMPUTER  = 300;

type
 TDbHlpCreateStorage = function(ServerIp, DBConnectionStr,ConfigPath : PChar; ServerType : Integer) : boolean;stdcall;
 TDbHlpSQLMonitor    = function(ServerIp, DBConnectionStr : PChar) : boolean; stdcall;
 TcrmUnpackFile      = function(const Source : PChar; const Target : PChar) : Integer; stdcall;
 TcrmPackFile        = function(const Source : PChar; const Target : PChar) : Integer; stdcall;

 TScanCounters = record
    // Общие счетчики
    cntStartTime : TDateTime;
    cntLastMeashureTime : TDateTime;
    cntRealThreadCount : Integer;
    cntThreadsFinished : Integer;
    cntAll : Integer;
    cntPassed : Integer;
    cntPowerOff : Integer;
    cntUnknown  : Integer; // При возобновлении сканирования
    cntAccessDenied : Integer;
    cntRegAccessDenied : Integer;
    cntUACActive : Integer;
    cntSkipped : Integer;

    cntRebooted : Integer;
    cntHibernationDisabled : Integer;
    cntBrandmauerEnabled : Integer;
    cntIndexingEnabled : Integer;
    cntUACDisabled : Integer;

    cleanedTemp : int64;
    cleanedDump : int64;
    cleanedBin : int64;
    cleanedKes : int64;
    cleanedTotal : int64;

    // KES counters
    kavOK  : Integer;
    kavRegPathNotFound : Integer;
    kavProtectionDisabled : Integer;
    kavServerWrong : Integer;
    kavAvpNotFound : Integer;
    kavAgentNotFound : Integer;
    kavAvpWrongConfigured : Integer;
    kavAgentWrongConfigured : Integer;
    kavAvpServiceIsNotRunning : Integer;
    kavAgentServiveIsNotRunning : Integer;
    // NT counters
    ntOK  : Integer;
    ntNoActualSP : Integer;
    ntWSUSClientFail : Integer;
    ntLowDiskSpace : Integer;
    ntWMIFailed : Integer;
    ntHibernated : Integer;
    ntTimeFailed : Integer;
    ntBadChannel : Integer;
    ntOSIsTooOld : Integer;
    ntNoRestartTooLong : Integer;
 end;

  TMruList  = class(TObject)
   private
    FCapacity : Integer;
    FRegPath : String;
    FFileList : TStringList;
    FCount : Integer;
    procedure Shift;
    procedure Rotate;
    procedure MakeTopAsSecond;
   public
    property Count : Integer read FCount;
    property FileList : TStringList read FFileList;
    constructor Create(const RegPath : String; Capacity : Integer);
    destructor Destroy; override;
    function  ItemExists(const FileName : String) : Integer;
    procedure ItemAdd(const FileName : String);
    function  Load : String;
    function  Save : String;
  end;

 const
  upd_par_Descr     = 'Description';
  upd_par_OSFlags   = 'OS flags';
  upd_par_Checked   = 'Selected';
  upd_par_RegPath   = 'RegFootPrint';
  upd_par_RegPath64 = 'RegFootPrint64';
 type

  TUpdateRecord = record
   updName         : String;
   updDescr        : String;
   updOSFlags      : DWORD;
   updChecked      : boolean;
   updRegPathx86   : String;
   updRegPathAMD64 : String;
  end;

  TUpdateList = class(TIniFile)
    private
     FFileName : String;
     FCurrentSection : String;
    public
     constructor Create(const IniFileName : String);
     destructor Destroy; override;
     procedure SetCurrentSection(const SectionTitle : String);
     function GetUpdatesForOS(OSCode : Integer; var sl : TStringList) : Integer;
     function ModifyUpdate(const UpdateRec : TUpdateRecord) : String;
     function DeleteUpdate(const UpdateName : String): String;
     function GetUpdateRecordForSection(var UR : TUpdateRecord) : boolean;
     function GetOSListByOSCode(OSFlag : DWORD): String;
     procedure SelectSection(isSelected : boolean);
  end;

  TEventLogErrorItem = record
    eleCodes  : String;
    eleSource : String;
    eleLogName: String;
    eleQuery  : String;
    eleMeaning: Integer;
  end;
  TAElErrors = array of TEventLogErrorItem;

const
 LW_KB = 1024;
 LW_MB = 1024 * 1024;
 LW_GB = 1024 * 1024 * 1024;

 LWC_LOG_SUCCESS = 0;
 LWC_LOG_WARNING = 1;
 LWC_LOG_ERROR = 2;
 LWC_LOG_DEBUG = 3;

 SHARE_SEPARATOR = Char(';');

 cfgDefaultFile = 'default.adc';
 cfgConfigKeyPhrase = 'dasT54#dkkvTRDsNbgd1sgjQM';
 CLRegPath   = '\Software\ArtLab\CARMA';
 CLMru       = '\Software\ArtLab\CARMA\Mru';
 CLRegPathUO = '\Software\ArtLab\CARMA\UnionReport';

 lwzgr_reg_user_utils = CLRegPath + '\Lists\Utils';
 lwzgr_reg_vendors    = CLRegPath + '\Vendors';
 lwzgr_reg_scan       = CLRegPath + '\Scan';
 lwzgr_reg_alert      = CLRegPath + '\Alerts';
 lwzgr_reg_Account    = CLRegPath + '\Accounts';
 lwzgr_reg_Parameters = CLRegPath + '\Parameters';
 lwzgr_reg_Routers    = CLRegPath + '\Routers';

 CL_ROOT_FOLDER    = 'CARMA';
 CL_PATH_Reports   = 'Reports';
 CL_PATH_Update    = 'Update';
 CL_PATH_CompLists = 'CompLists';
 CL_PATH_FilPerFil = 'FilePerFilter';    // One file per filter
 CL_PATH_CORP_SYS  = 'CorpSystems';
 CL_PATH_Networks  = 'Networks';         // ip-ranges
 CL_PATH_Filters   = 'Filters';
 CL_PATH_SCANSESS  = 'Scansess';
 CL_PATH_TEMPLATES = 'Templates';
 CL_PATH_ENV_HIST  = 'EnvHistory';
 CL_PATH_REDISTR   = 'Redistr';

 update_pckg    = 'updatepckg.exe';
 updater_module = 'scanupdater.exe';
 updates_file   = 'ntkblist.ini';

 repCompExt = 'comp';

 TAG_NO_HIDE_TAB = 777;

 SCAN_METHOD_NORMAL = 0;
 SCAN_METHOD_AGRESSIVE = 1;

 SCAN_THREAD_MIN = 1;
 SCAN_THREAD_MAX = 62;

 SCAN_THREAD_MAX_AGGRESSIVE = 124;

 SCAN_COMP_TIME_LIMIT_MIN = 8;
 SCAN_COMP_TIME_LIMIT_MAX = 32;

 SCAN_FULL_TIME_LIMIT_MIN = 90;
 SCAN_FULL_TIME_LIMIT_MAX = 180;

 CONNECT_METHOD_IP = 0;
 CONNECT_METHOD_NAME = 0;

 COMPRESSION_DISABLE_IGNORE = 0;
 COMPRESSION_DISABLE_ALWAYS = 1;
 COMPRESSION_DISABLE_DISK_FREE = 2;

 SHELL_SUCCESS_HI = 32;

 MAX_MRU_COUNT = 10;

 SCAN_RESTRICT_EVENTLOG = 24;
 SCAN_RESTRICT_CLEANER  = 24;
 SCAN_RESTRICT_UNCOMPRESS  = 60;
 SCAN_RESTRICT_FAKE_SESSION  = 120;

 CUF_ACCOUNT_MISSING       = 1;
 CUF_ACCOUNT_EXPIRED       = 1 shl 1;
 CUF_ACCOUNT_LOCKED        = 1 shl 2;
 CUF_ACCOUNT_PASSW_EXPIRED = 1 shl 3;
 CUF_ACCOUNT_DISABLED      = 1 shl 4;

type
 TServerType = record
   stCode : Integer;
   stName : String;
 end;
 TScanOptionsShapshot = record
  so_scanUseWMI             : boolean;
  so_scanUseSpreadLog       : boolean;
  so_scanActivateProfiling  : boolean;
  so_scanIdentifyUser       : boolean;
  so_scanIdentifyUserAlways : boolean;
  so_scanCompName           : boolean;
  so_scanCleanTempFolders   : boolean;
  so_scanCleanBins          : boolean;
  so_scanCleanAddFolder     : boolean;
  so_scanCleanAddService    : boolean;
  so_DisableHibernation     : boolean;
  so_DisableUAC             : boolean;
  so_scanImmediatellySaving : boolean;
  so_scanEnableBrandmauer   : boolean;
  so_scanEnableRemRegistry  : boolean;
  so_scanReadEventlogQuery  : boolean;
  so_scanReadEventlogScan   : boolean;
  so_scanEventLogByWMI      : boolean;
  so_scanEventLogExtractText: boolean;
  so_scanGetTasks           : boolean;
  so_scanGetSoftMSI         : boolean;
  so_scanGetSoftUninstall   : boolean;
  so_scanGetWinUpdates      : boolean;
  so_scanDCOMParams         : boolean;
  so_scanGetSvcDrv          : boolean;
  so_scanGetUsrGrp          : boolean;
  so_scanControlAdmGroups   : boolean;
  so_scanCheckInternetSvc   : boolean;
  so_scanCheckCritUpdates   : boolean;
  so_scanFixFakeSessions    : boolean;
  so_scanFixWrongDNSNames   : boolean;
  so_scanCheckTempFilders   : boolean;

  so_ScanCompressionPolicy  : Integer;
  so_ScanEnableDriveIndexing     : boolean;

  so_WMI_ShowPhysNetAdaptersOnly : boolean;   // Не кешируется для индивидуальных опросов

  so_ActionRestart          : boolean;
 end;

 TReportUnion = record
   ruADComp       : boolean;
   ruADUser       : boolean;
   ruSessions     : boolean;
   ruLogicalDrive : boolean;
   ruDiskSystem   : boolean;
   ruHardware     : boolean;
   ruPrinters     : boolean;
   ruNetworkParam : boolean;
   ruSoftware     : boolean;
   ruUpdates      : boolean;
   ruEnvVar       : boolean;
   ruProcesses    : boolean;
   ruServices     : boolean;
   ruConnections  : boolean;
   ruUsers        : boolean;
   ruEvents       : boolean;
 end;

 const

 AServerType : array[0..SRV_TYPE_UNKNOWN] of TServerType =
 (
  (stCode : SRV_TYPE_ANY;     stName : _SRV_TYPE_ANY),
  (stCode : SRV_TYPE_DC;      stName : _SRV_TYPE_DC),
  (stCode : SRV_TYPE_SCCM;    stName : _SRV_TYPE_SCCM),
  (stCode : SRV_TYPE_ANTIVIR; stName : _SRV_TYPE_ANTIVIR),
  (stCode : SRV_TYPE_WSUS   ; stName : _SRV_TYPE_WSUS),
  (stCode : SRV_TYPE_FILE;    stName : _SRV_TYPE_FILE),
  (stCode : SRV_TYPE_FTP;     stName : _SRV_TYPE_FTP),
  (stCode : SRV_TYPE_WEB;     stName : _SRV_TYPE_WEB),
  (stCode : SRV_TYPE_SQL;     stName : _SRV_TYPE_SQL),
  (stCode : SRV_TYPE_UNKNOWN; stName : _SRV_TYPE_UNKNOWN)
  );

 AEvlErrors : array [0..1] of TEventLogErrorItem =
 (
  (eleCodes : '';  eleSource : 'disk'; eleLogName : 'System'; eleQuery : 'SELECT * FROM Win32_NTLogEvent where Logfile =' + ''''+ 'System' + '''' + 'and (EventCode=7 or EventCode=11 or EventCode=51)'; eleMeaning : EVL_MEAN_DISK),
  (eleCodes : '';  eleSource : 'System Error'; eleLogName : 'System'; eleQuery : 'SELECT * FROM Win32_NTLogEvent where EventCode=1003'; eleMeaning : EVL_MEAN_PHYSMEMORY)
 );

 AResShareNames : array[0..5] of String =
 (
  'Brother',
  'Cannon',
  'Epson',
  'HP',
  'Samsung',
  'Xerox'
 );
const
 // CSSTATUS ... Linked with ImageIndex for lvAllComputers !!!
  CSTATUS_UNDEF         = 0;

 LC_EMPTY_STRING = '';
 LC_EMPTY_VALUE  = -1;
 LC_STR_ZERO     = '0';

 ConfigFileExt = 'adc';
 SrvFile = 'srvlist.txt';
 ADFltFile = 'ADFlt.txt';
 NetwFltFile = 'NetwFlt.txt';
 AppLogFile = 'carma.log';
 LdapLog = 'ldap.log';
 cNameGeo = 'names_geo.txt';
 cNameOrg = 'names_org.txt';
 nmapTemplates = 'nmapcmd.txt';

 PORT_DEF_RADMIN  = 4899;
 PORT_DEF_VNC     = 4900;

var

 glbPortableBehaviour : boolean = false;
 glbSrvFile : String = LC_EMPTY_STRING;
 glbADFilterFile : String = LC_EMPTY_STRING;
 glbNetworkFilterFile : String = LC_EMPTY_STRING;
 glbAppLogFile : String = LC_EMPTY_STRING;
 glbLdapLogFile : String = LC_EMPTY_STRING;
 glbCNamesGeoFile : String = LC_EMPTY_STRING;
 glbCNamesOrgFile : String = LC_EMPTY_STRING;
 glbNmapCommands : String = LC_EMPTY_STRING;
 glbDBLibrary : String = LC_EMPTY_STRING;
 glbPackLibrary : String = LC_EMPTY_STRING;

 {$IFDEF DEBUG_VER}
  dbgScan : TDebugSection;
 {$ENDIF}

 glbScanShadowHandler  : HWND = 0;
 glbScanCounters : TScanCounters;
 glbNTUpdateList : TUpdateList;

 glb_AppMainWndHandle : HWND;
 glb_AppHandle        : THandle;
 glb_AppFailStartup   : boolean = false;
 glb_AppTerminating   : boolean = false;
 glb_AppIsStylized    : boolean = false;
 glb_IsApp64          : boolean;
 glb_IsOS64           : boolean;
 glb_OS_Version       : DWORD;
 glb_OS_SPVersion     : DWORD;
 glb_OS_VersionSTR    : String;
 glb_RAM_Size         : int64;
 glb_DBLibraryHandle  : THandle;
 glb_PackLibraryHandle: THandle;

 glb_ServerConfigFile : String = '';
 glb_DefaultHostsFile : String = '';

 glb_AppHasAdminPriv : boolean;
 glb_SysPaths        : TCLSystemPaths;
 glb_InstallPackage  : String;
 glb_Installer       : String;
 glb_MMC_Runner      : String;

 glb_ADPresent           : boolean = false;
 glb_UACEnabled          : boolean = false;
 glb_DomainName          : String = LC_EMPTY_STRING;
 glb_DomainFirstName     : String = LC_EMPTY_STRING;
 glb_DomainDCName        : String = LC_EMPTY_STRING;
 glb_DomainCanonicalName : String = LC_EMPTY_STRING;
 glb_AppUserName         : String = LC_EMPTY_STRING;
 glb_ADUserHumanName     : String = LC_EMPTY_STRING;
 glb_ADUserPhone         : String = LC_EMPTY_STRING;
 glb_ADUserEMail         : String = LC_EMPTY_STRING;
 glb_DomainUserName      : String = LC_EMPTY_STRING;
 glb_AntimonMode         : boolean = true;
 glb_DebugDumpTempInfo   : boolean = false;

 glb_AppSelfIP           : String;
 glb_SelfComputerName    : String;
 glb_envHostIpInfo       : THostAdapterInfo;

 glb_AppVersion          : String  = LC_EMPTY_STRING;
 glb_AppIsRunInTerminal  : boolean = false;    // WTSOpenServerExW etc. failed in Terminal session (for me)

 glb_ShellDocument    : String = '';

 glb_PathExe          : String = LC_EMPTY_STRING;
 glb_PathUtils        : String;
 glb_PathAppData      : String;
 glb_PathCompLists    : String;
 glb_PathCopmListsFxF : String;
 glb_PathCopmListsCS  : String;
 glb_PathCopmListsNetw: String;
 glb_PathReports      : String;
 glb_PathReportsComp  : String;
 glb_PathTemp         : String;
 glb_PathDebug        : String;
 glb_PathUpdate       : String;
 glb_PathFilters      : String;
 glb_PathSMSAdminUI   : String = LC_EMPTY_STRING; // New LanWeather2
 glb_PathRepSess      : String = LC_EMPTY_STRING;
 glb_PathTemplates    : String = LC_EMPTY_STRING;
 glb_PathEnvHistory   : String = LC_EMPTY_STRING;
 glb_PathPowerShell   : String;
 glb_PathSystemSounds : String = LC_EMPTY_STRING;

 glb_TermClientPresent    : boolean = false;
 glb_SMSRemoteToolPresent : boolean = false;
 glb_RadminPresent        : boolean = false;
 glb_TightVNCViewerPresent: boolean = false;
 glb_TightVNCServerPresent: boolean = false;
 glb_CNameTemplatesPresent: boolean = false;

 glb_AppTerminateEvent   : THandle;
 glb_ScanTerminateEvent  : THandle;
 glb_ICMPTerminateEvent  : THandle;
 glb_EnvMonCommandEvent  : THandle;

 glb_DecryptedUserName    : String;
 glb_DecryptedUserPassw   : String;
 glb_DecryptedUserNameAnDom : String;
 glb_DecryptedUserPasswAnDom: String;

 glb_CompNamesGeo : TStringList = nil;
 glb_CompNamesOrg : TStringList = nil;
 glb_FoldersToClear : TStringList = nil;
 glb_ServicesToDelete : TStringList = nil;

 glb_KESServerNames : TStringList;

 glb_HelpFile     : String;
 glb_AgentVerStr  : String;
 glb_AgentExe     : String;
 glb_AgentPresent : boolean = false;

 glb_MessengerVerStr  : String;
 glb_MessengerExe     : String;
 glb_MessengerPresent : boolean = false;

 glb_PaExeFile : String;
 glb_PsExeFile : String;

 glb_Rexec_Storage: String;
 glb_CE_Storage : String;
 glb_WKGr_Storage : String;
 glb_Utils_Storage : String;
 glb_BitAct_Storage : String;
 glb_Report_Storage : String;
 glb_Env_Storage : String;
 glb_DCOMFav_Storage : String;

 glb_BitActPageIndex : Integer = 0;

 glbSpreadLogName : String = 'Carma';
 glbSpreadLogMessageFile : String;
 glbSpreadLogEventSource : String = 'CarmaEvtSource';
 glbSpreadLogApp : String = 'CarmaSuite';
 glb_SpreadLogVerStr : String;

 appRunCount : Integer = 0;
 appLocale : Integer = LOCALE_ENGLISH;
 appLProfilePolicy : Integer = 0;
 appBottomPanelHeight : Integer = 300;
 appMinimizeToTray : boolean = false;
 appAutoClipboard : boolean = true;
 appColorizeItems  : boolean = false;
 appNoHidePassw : boolean = false;
 appNoBorders : boolean = false;
 appDrawListLines : boolean = false;
 appShowButtonText : boolean = true;
 appFontSize       : Integer = 9;
 appSrvGroupView   : boolean = false;
 appStopMonitorOnFailKESState : boolean = false;
 appStartMonitorOnGoodKESState : boolean = false;
 appHostsFile : String = '';
 appResolveIpAddresses : boolean = false;
 appResolveIpAddressesFlt : boolean = true;
 appResolveComputerNames : boolean = false;
 appAddResolvedOnly : boolean = true;
 appRedistrFolderPath : String;

 appLoadLastList : boolean = true;
 appShowAssistant : boolean = true;
 appUseUpdate : boolean = false;
 appUpdateSource : String;
 appUpdateIsReady : boolean;
 appNmapIndex : Integer;
 appAnotherDomModeEnabled : boolean;
 appAnotherDomName : String;

 vendRemAssistantFile : String;

 vendTermClientPath   : String;
 vendRadminPath       : String;
 vendRadminPort       : Integer= PORT_DEF_RADMIN;

 vendTightVNCViewerPath  : String;
 vendTightVNCServerPath  : String;
 vendTightVNCHooksPath   : String;

 vendTightVNCPort        : Integer = PORT_DEF_VNC;

 vendUltraVNCViewerPath  : String;

 vendNmapPath : String;

 vendUseDefaultBrowser : boolean = true;
 vendBrowserPath       : String;
 vendBrowserAddSearchString : String;
 vendBrowserUseAddSearchString : boolean = false;

 intSCCMDefaultServer : String;
 intSMSRemoteToolApp  : String;
 intSMSUseServerName  : boolean;
 intKaspersky         : boolean;
 intKESOutOfBases     : Integer = 7;

 scanThreadCount        : Integer = 8;
 scanMethod             : Integer = 0;
 scanPriotiryBoost      : boolean = true;
 scanComputerTimeLimit  : Integer = SCAN_COMP_TIME_LIMIT_MIN;
 scanFullTimeLimit      : Integer = SCAN_FULL_TIME_LIMIT_MIN;
 scanSaveSpan           : Integer = 400;
 scanEvaluateComputers  : boolean = true;
 scanSelectProblems     : boolean = true;
 scanCreateNetworkList  : boolean = true;
 scanImmediateListSaving: boolean = false;
 scanSkipVisibilityTest : boolean = false;
 scanUseWMI             : boolean = true;
 scanActivateProfiling  : boolean = true;
 scanReadEventlogScan   : boolean = false;
 scanReadEventlogQuery  : boolean = false;
 scanInstallAgentScan   : boolean = false;
 scanInstallAgentQuery  : boolean = false;
 scanIdentifyUser       : boolean = true;
 scanIdentifyUserAlways : boolean = true;
 scanCheckCompName      : boolean = false;
 scanCheckInternetSvc   : boolean = false;
 scanCheckCritUpdates   : boolean = false;
 scanDeleteShares       : boolean = false;
 scanEnableBrandmauer   : boolean = false;
 scanEnableRemRegistry  : boolean = false;
 scanEnableIndexing     : boolean = false;
 scanDisableCompressionPolicy : Integer;
 scanDCOMParams         : boolean = false;

 scanSrvOnAppStart      : boolean = false;
 MonEnvOnAppStart       : boolean = false;

 scanCleanTempFolders   : boolean = false;
 scanCleanBins          : boolean = false;
 scanCleanSpoolers      : boolean = false;
 scanShowPhysNetAdaptersOnly : boolean = false;
 scanGetTasks : boolean = false;
 scanGetSoft : boolean = false;
 scanGetSoftUninstall : boolean = false;
 scanGetUpdates : boolean = false;
 scanGetSvcDrv: boolean = true;
 scanGetUsrGrp: boolean = true;
 scanControlAdmGroups : boolean = false;
 scanNativeReadEvents : boolean = false;
 scanDoNotExtractEventText : boolean = true;
 scanFixFakeSessions : boolean = false;
 scanFixWrongDNSNames : boolean = true;
 scanCheckTempFolders : boolean = false;

 scanCleanAddFolder : boolean = false;
 scanCleanAddService: boolean = false;
 scanUseSpreadLogging : boolean = false;

 // All actions disabled by default
 scanacRestartComp      : boolean = false;
 scanacDisableHibernation : boolean = false;
 scanacProblemKES       : boolean = false;
 scanacProblemSCCM      : boolean = false;
 scanacProblemWMI       : boolean = false;
 scanacProblemPrintJ    : boolean = false;
 scanacAlive            : boolean = false;
 scanacDisableUAC       : boolean = false;
 scanacEnableDCOM       : boolean = false;

 parConnectMethod       : Integer = 0;

 critSlowChannel         : Integer = 300;
 critNotEnoughtDiskSpace : Integer = 15;
 critOSInstalledYearsAgo : Integer = 9;
 critWSUSDoesNotWork     : Integer = 40;
 critCompDoesNotRestart  : Integer = 30;
 critTimeDifference      : Integer = 5;
 critRAMSize             : Integer = 1024;
 critPwdAgeDays          : Integer = 30;
 critCodePage            : String  = '0419';

 critRestartText         : String;
 critRestartDelay        : Integer = 0;

 accImplicitAccount      : boolean;
 accImplicitAccountAnDom : boolean;
 accUserName             : string;
 accUserPassword         : string;
 accUserNameAnDom        : string;
 accUserPasswordAnDom    : string;
 accUpdateFtpUName       : String;
 accUpdateFtpUPassw      : String;
 accAddDomainSuffix      : boolean;
 accDomainSuffix         : String;

 prxUse                  : boolean = false;
 prxServer               : String;
 prxUser                 : String;
 prxPassword             : String;

 snmpCommunityString     : string = 'public';
 snmpGetRouteTable       : boolean = false;
 snmpRefreshInterval     : Integer = 5;

 DbHlpCreateStorage : TDbHlpCreateStorage= nil;
 DbHlpSQLMonitor    : TDbHlpSQLMonitor= nil;
 crmUnpackFile      : TcrmUnpackFile = nil;
 crmPackFile        : TcrmPackFile = nil;

 procedure gfAppLocaleRead;
 procedure gfApplyLanguageSettings(AppDir : String);
 function  gfGetLocaleLibraryName : String;
 function  gfGetExtForLocale : String;

 procedure gfConfigureMM;
 procedure gfInitExternalLibraries;
 function  gfDBLibraryLoad : boolean;
 procedure gfDBLibraryFree;
 function  gfPackLibraryLoad : boolean;
 procedure gfPackLibraryFree;

 procedure gfSettingsRead;
 procedure gfSettingsWrite;
 procedure gfUnionOptRead(var UO : TReportUnion);
 procedure gfUnionOptWrite(UO : TReportUnion);
 function  gfUpdateIsReady: boolean;
 procedure gfCustomizeLocalRedistrPath;

 function  gfCheckImAlone: boolean;
 procedure gfLoadEnvironment;
 procedure gfEnablePrivileges;
 procedure gfADCheckPresent;
 procedure gfIdentCurrentUserAttr;
 function  gfGetDomainUserName : String;

 procedure gfGetAppDataDir;
 procedure gfCheckAndCreateDir(path: String);
 procedure gfAppUpdateDirs;
 procedure gfSendMessageToGUI(Msg: String);
 function  gfInputString(const aCaption,aPrompt,aText : String) : String;
 function  lwldapDomainNameToLdapName(dname : String) : String;
 function  gfModifyTrusteeNameWithSuffix(const Trustee : String) : String;

 function  gfShareNameIsReserved(sName : String) : boolean;

 function  gfRedirectLoad: boolean;
 procedure gfWow64DisableRedirection(var EnableRedirection: boolean);
 procedure gfWow64EnableRedirection(var EnableRedirection: boolean);

 procedure gfEncryptSecrets;
 procedure gfDecryptSecrets;

 procedure gfScanGetOptions(var SO : TScanOptionsShapshot; SelectAll : boolean = false);

 procedure gfPlaySystemSound(FileName : String);

 function  gfEventLogNeeds(ELName : String) : boolean;

 procedure gfOpenURL(URL : String);

type
  TWow64DisableWow64FsRedirection = function(var Wow64FsEnableRedirection: LongBool): LongBool; stdcall;
  TWow64EnableWow64FsRedirection = function(var Wow64FsEnableRedirection: LongBool): LongBool; stdcall;

 var
  Wow64DisableWow64FsRedirection: TWow64DisableWow64FsRedirection;
  Wow64EnableWow64FsRedirection: TWow64EnableWow64FsRedirection;
  glb_RedirectLoaded: boolean;

implementation
uses
  Registry, Controls, ShellApi, SHFolder, StrUtils, mmSystem, Utils.Forms,  Cnst.Messages,
  FmInputBox, Collection.Servers,  Wapi.Netapi32, Wapi.Crypt, Obj.FileVerInfo,
  Wapi.Advapi, Collection.Agent, Collection.Msng, Obj.LdapMaster, Wapi.Wts, Utils.Common,
  Utils.OS, Wapi.NTNative, Wapi.IpHlp, Utils.Crypt;

// ***************************************************************
// Get locale settings must be performed before load localization libraries
// ***************************************************************
procedure gfAppLocaleRead;
var
  hReg: TRegistry;
begin
  hReg := TRegistry.Create();
  hReg.RootKey := HKEY_CURRENT_USER;
  try
    // Common section
    if hReg.OpenKey(CLRegPath, true) then with hReg do begin
     if ValueExists('appLocale') then appLocale := ReadInteger('appLocale');
    end;
  finally
    FreeAndNil(hReg);
  end;
end;
// *****************************************************************************
// gfApplyLanguageSettings
// *****************************************************************************
procedure gfApplyLanguageSettings(AppDir : String);
var
 LangMask : String;
 LangFiles : TStringList;
begin
 if (appLocale = LOCALE_RUSSIAN) then begin
  luDeleteFilesInDirectoryRecursive(AppDir, '*.enu', false);
  exit;
 end;
 LangMask := gfGetExtForLocale();
 LangFiles := TStringList.Create();
 try
  luCreateDirList(AppDir + '\lang', LangFiles, false, LangMask);
  luCopyFileList(LangFiles, AppDir, false, false);
 finally
  FreeAndNil(LangFiles);
 end;
end;
// *****************************************************************************
// gfGetLocaleLibraryName
// *****************************************************************************
function  gfGetLocaleLibraryName : String;
begin
 case appLocale of
   LOCALE_ENGLISH : result := APP_NAME + '.enu';
    else
     result := LC_EMPTY_STRING;
 end;
end;
// *****************************************************************************
// gbGetExtForLocale
// *****************************************************************************
function gfGetExtForLocale : String;
begin
 case appLocale of
   LOCALE_ENGLISH : result := '*.enu';
    else
     result := LC_EMPTY_STRING;
 end;
end;
// **********************************************************************
// Check for single copy
// **********************************************************************
function gfCheckImAlone: boolean;
var
  UniqueMapping: THandle;
  dwLastError : DWORD;
begin
 result := true;
 UniqueMapping := CreateFileMapping(INVALID_HANDLE_VALUE, nil, PAGE_READONLY, 0, 32, 'CARMA is cool!');
 if (UniqueMapping = 0) then begin
   Windows.MessageBox(0, PChar('Failed to get memory!'), PChar(PROP_ERROR), MB_OK);
   result := false;
   glb_AppFailStartup := true;
 end else begin
   dwLastError := GetLastError();
   if (dwLastError = ERROR_ALREADY_EXISTS) then  begin
   Windows.MessageBox(0, PChar(COMMON_APP_SINGLE), PChar(PROP_ERROR), MB_OK);
   result := false;
   glb_AppFailStartup := true;
  end;
 end;
end;
// *******************************************************************
//  gfLoadEnvironment
// *******************************************************************
procedure gfLoadEnvironment;
begin
 glb_IsApp64    := (SizeOf(Pointer) = 8);
 ipGetSelfIpInfoEx(glb_envHostIpInfo);
 glb_AppVersion := lwGetStringVersion(Application.ExeName);
 glb_AppIsRunInTerminal := sys2IsAppInTerminalSession();
 gfInitExternalLibraries();
 glbSrvFile := ExtractFilePath(Application.ExeName) + '\' + SrvFile;
 glb_AppSelfIP       := ipGetSelfIpV4();
 glb_SelfComputerName:= ipGetSelfComputerName();
 glb_AppHasAdminPriv := sys2IsAdmAccount();
 glb_IsOS64          := sys2IsOS64();
 glb_RAM_Size        := sys2GetPhysicalMemoryFromRegistry();
 sys2GetSystemPaths('', glb_SysPaths, true);
 {$IFNDEF ROAMING}
  glb_SysPaths.prfCurrentUserDir := luGetEnvVarValue('USERPROFILE');    // Disabled 19.10.2017
 {$ELSE}
  glb_SysPaths.prfCurrentUserDir := luGetSpecialFolder(CSIDL_APPDATA);    // Virtualization
 {$ENDIF}
 glb_PathSystemSounds := glb_SysPaths.rsWinDir + 'Media';
 gfEnablePrivileges();
 glb_AppUserName := sys2GetUsersName();
 gfADCheckPresent();
 glb_DomainUserName := gfGetDomainUserName();
 if glb_ADPresent and (glb_DomainUserName <> LC_EMPTY_STRING) then
  gfIdentCurrentUserAttr();
end;
// ***************************************************************
// gfEnablePrivileges
// ***************************************************************
procedure gfEnablePrivileges;
begin
 sys2SetProcessPriv(SE_DEBUG_NAME);
 sys2SetProcessPriv(SE_SHUTDOWN_NAME);
 sys2SetProcessPriv(SE_PROF_SINGLE_PROCESS_NAME);
 sys2SetProcessPriv(SE_TAKE_OWNERSHIP_NAME);
 sys2SetProcessPriv(SE_SYSTEM_PROFILE_NAME);
 sys2SetProcessPriv(SE_INC_BASE_PRIORITY_NAME);
 sys2SetProcessPriv(SE_INCREASE_QUOTA_NAME);
 sys2SetProcessPriv(SE_INCREASE_WORKING_SET);
 sys2SetProcessPriv(SE_LOAD_DRIVER_NAME);
 sys2SetProcessPriv(SE_RESTORE_NAME);
 sys2SetProcessPriv(SE_TCB_NAME);
end;
// ***************************************************************
// gfConfigureMM
// ***************************************************************
procedure gfConfigureMM;
var
 MBA : TMinimumBlockAlignment;
begin
  MBA := GetMinimumBlockAlignment;
  System.NeverSleepOnMMThreadContention := true;
end;
// ***************************************************************
// gfInitExternalLibraries
// ***************************************************************
procedure gfInitExternalLibraries;
begin
  DllLoadNetapi(true);
  DllLoadAdvapi(true);
  LoadDllWts(true);
  LoadDllNtDll(true);
  LoadDllIpHlp(false, glb_OS_Version);
end;
// ***************************************************************
// gfDBLibraryLoad
// ***************************************************************
function gfDBLibraryLoad : boolean;
var
 dwLastError : DWORD;
begin
 result := false;
 if not FileExists(glbDBLibrary) then begin
   fuError(format(COMMON_APP_MODULE_MISSING, [glbDBLibrary]));
   exit;
 end;
 hLib := LoadLibrary(PChar(glbDBLibrary));
 if (hLib = INVALID_HANDLE_VALUE) then begin
   dwLastError := GetLastError();
   fuError(format(COMMON_APP_MODULE_FAILED, [glbDBLibrary, dwLastError, SysErrorMessage(dwLastError)]));
   exit;
 end;
 DbHlpCreateStorage := GetProcAddress(hLib, PChar('DbHlpCreateStorage'));
 DbHlpSQLMonitor   := GetProcAddress(hLib, PChar('DbHlpSQLMonitor'));
 result := true;
end;
// ***************************************************************
// gfDBLibraryFree
// ***************************************************************
procedure gfDBLibraryFree;
begin
 FreeLibrary(glb_DBLibraryHandle);
end;
// ***************************************************************
// gfPackLibraryLoad
// ***************************************************************
function  gfPackLibraryLoad : boolean;
var
 dwLastError : DWORD;
begin
 result := false;
 if not FileExists(glbPackLibrary) then begin
   fuError(format(COMMON_APP_MODULE_MISSING, [glbPackLibrary]));
   exit;
 end;
 hLib := LoadLibrary(PChar(glbPackLibrary));
 if (hLib = INVALID_HANDLE_VALUE) then begin
   dwLastError := GetLastError();
   fuError(format(COMMON_APP_MODULE_FAILED, [glbPackLibrary, dwLastError, SysErrorMessage(dwLastError)]));
   exit;
 end;
 crmUnpackFile := GetProcAddress(hLib, PChar('crmUnpackFile'));
 crmPackFile   := GetProcAddress(hLib, PChar('crmPackFile'));
 result := true;
end;
// ***************************************************************
// gfPackLibraryFree
// ***************************************************************
procedure gfPackLibraryFree;
begin
 FreeLibrary(glb_PackLibraryHandle);
end;
// ***************************************************************
// gfIdentCurrentUserAttr
// ***************************************************************
procedure gfIdentCurrentUserAttr;
var
 pLdapMaster   : TLdapMaster;
 lUser         : PTLDAPUser;
 LDAPError     : String;
 LDAPSucceeded : boolean;
 ErrorString   : String;
begin
 lUser := nil;
 try
  New(lUser);
  pLdapMaster := TLdapMaster.Create(nil, lUser, true, '');
   try
    LDAPSucceeded := pLdapMaster.LdapPrepare(LDAPError);
    if not LDAPSucceeded then begin
     fuError(LDAPError);
     exit;
    end;

    if pLdapMaster.GetUserInfo(glb_AppUserName, ErrorString) then begin
     glb_ADUserHumanName  := lUser.cn;
     glb_ADUserPhone      := lUser.telephoneNumber;
     glb_ADUserEMail      := lUser.mail;
    end;
  except
   On E: Exception do begin
   end;
  end;
 finally
   FreeAndNil(pLdapMaster);
   Dispose(lUser);
 end;
end;
// ***************************************************************
// Check for AD present and assign AD DCName
// ***************************************************************
procedure gfADCheckPresent;
begin
  try
    glb_ADPresent := sys2ADPresent(glb_DomainName);
    if glb_ADPresent then begin
     glb_DomainFirstName := Copy(glb_DomainName, 1, Pos('.', glb_DomainName) -1 );
     glb_DomainDCName := sys2GetDCName();
     glb_DomainDCName := ReplaceStr(glb_DomainDCName, '\\', '') + '.' + glb_DomainName;
    end;
  except
    glb_ADPresent := false;
    glb_DomainDCName := '';
  end;
end;
// ***************************************************************
// gfGetDomainUserName
// ***************************************************************
function  gfGetDomainUserName : String;
begin
 result := glb_AppUserName;
 if (glb_DomainName = LC_EMPTY_STRING) then exit;
 if (Pos('.', glb_DomainName) = 0) then exit;
 result := Copy(glb_DomainName, 1, Pos('.', glb_DomainName) -1 ) + '\' +
   glb_AppUserName;
end;
// ***************************************************************
// Common application data directory
// ***************************************************************
procedure gfGetAppDataDir;
var
 {$IFNDEF ROAMING}
   hReg: TRegistry;
 {$ENDIF}
  sRegPath: String;
begin
  {$IFNDEF ROAMING}
   hReg := TRegistry.Create();
   try
     hReg.RootKey := HKEY_LOCAL_MACHINE;
     sRegPath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders';
     if hReg.OpenKeyReadOnly(sRegPath) then begin
       glb_PathAppData := hReg.ReadString('Common AppData');
       glb_PathAppData := glb_PathAppData + '\' + CL_ROOT_FOLDER;
     end;
  finally
     FreeAndNil(hReg);
   end;
  {$ELSE}
     glb_PathAppData := glb_SysPaths.prfCurrentUserDir + '\' + CL_ROOT_FOLDER;
  {$ENDIF}
end;
// ***************************************************************
// gfUpdateIsReady
// ***************************************************************
function  gfUpdateIsReady: boolean;
var
  hReg: TRegistry;
begin
  result := false;
  hReg := TRegistry.Create();
  hReg.RootKey := HKEY_CURRENT_USER;
  try
   if hReg.OpenKey(CLRegPath, true) then
    if hReg.ValueExists('appUpdateIsReady') then
     result := (hReg.ReadBool('appUpdateIsReady') = true);
  finally
    FreeAndNil(hReg);
  end;
end;
// ***************************************************************
// CheckAndCreateDir
// ***************************************************************
procedure gfCheckAndCreateDir(path: String);
var
  le: DWORD;
begin
 try
  if not DirectoryExists(path) then
   if not ForceDirectories(path) then begin
    le := GetLastError();
    fuError(PChar(format(COMMON_ERR_DIR_MAKE, [path, le, SysErrorMessage(le)])));
  end;
 except
  On E: Exception do begin
   fuError(PChar(format(SYS_EXCEPT_DIR_CREATE, [path, E.Message])));
  end;
 end;
end;
// *******************************************************************
//  gfSettingsRead
// *******************************************************************
procedure gfSettingsRead;
var
  hReg: TRegistry;
begin
 hReg := TRegistry.Create();

 vendTermClientPath     := glb_SysPaths.rsSysDir + '\mstsc.exe';
 vendTightVNCViewerPath := glb_PathExe + 'VNC\tvnviewer.exe';
 vendTightVNCServerPath := glb_PathExe + 'VNC\tvnserver.exe';

 vendRemAssistantFile   := glb_SysPaths.rsSysDir + '\msra.exe';

 try
  hReg.RootKey := HKEY_CURRENT_USER;
  if hReg.OpenKey(CLRegPath, true) then with hReg do begin

    if ValueExists('appRunCount') then appRunCount := ReadInteger('appRunCount');
    if ValueExists('appLProfilePolicy') then appLProfilePolicy := ReadInteger('appLProfilePolicy');
    if ValueExists('appBottomPanelHeight') then appBottomPanelHeight := ReadInteger('appBottomPanelHeight');
    if ValueExists('appMinimizeToTray') then appMinimizeToTray := ReadBool('appMinimizeToTray');
    if ValueExists('appAutoClipboard') then appAutoClipboard := ReadBool('appAutoClipboard');

    if ValueExists('appColorizeItems') then appColorizeItems := ReadBool('appColorizeItems');
    if ValueExists('appNoHidePassw') then appNoHidePassw := ReadBool('appNoHidePassw');

    if ValueExists('appNoBorders') then appNoBorders := ReadBool('appNoBorders');
    if ValueExists('appDrawListLines') then appDrawListLines := ReadBool('appDrawListLines');
    if ValueExists('appShowButtonText') then appShowButtonText := ReadBool('appShowButtonText');

    if ValueExists('appFontSize') then appFontSize := ReadInteger('appFontSize');
    if ValueExists('appSrvGroupView') then appSrvGroupView := ReadBool('appSrvGroupView');

    if ValueExists('appStopMonitorOnFailKESState') then appStopMonitorOnFailKESState := ReadBool('appStopMonitorOnFailKESState');
    if ValueExists('appStartMonitorOnGoodKESState') then appStartMonitorOnGoodKESState := ReadBool('appStartMonitorOnGoodKESState');
    if ValueExists('appHostsFile') then appHostsFile := ReadString('appHostsFile');
    if ValueExists('appResolveIpAddresses') then appResolveIpAddresses := ReadBool('appResolveIpAddresses');
    if ValueExists('appResolveIpAddressesFlt') then appResolveIpAddressesFlt := ReadBool('appResolveIpAddressesFlt');
    if ValueExists('appResolveComputerNames') then appResolveComputerNames := ReadBool('appResolveComputerNames');
    if ValueExists('appAddResolvedOnly') then appAddResolvedOnly := ReadBool('appAddResolvedOnly');
    if ValueExists('appRedistrFolderPath') then appRedistrFolderPath := ReadString('appRedistrFolderPath');

    if ValueExists('appLoadLastList') then appLoadLastList := ReadBool('appLoadLastList');
    if ValueExists('appShowAssistant') then appShowAssistant := ReadBool('appShowAssistant');

    if ValueExists('appUseUpdate') then appUseUpdate := ReadBool('appUseUpdate');
    if ValueExists('appUpdateSource') then appUpdateSource := ReadString('appUpdateSource');

    if ValueExists('appNmapIndex') then appNmapIndex := ReadInteger('appNmapIndex');

    if ValueExists('appAnotherDomModeEnabled') then appAnotherDomModeEnabled := ReadBool('appAnotherDomModeEnabled');
    if ValueExists('appAnotherDomName') then appAnotherDomName := ReadString('appAnotherDomName');

    CloseKey();
  end;
   // Parameters section
  if hReg.OpenKey(lwzgr_reg_Parameters, true) then with hReg do begin
    if ValueExists('parConnectMethod') then parConnectMethod := ReadInteger('parConnectMethod');
    CloseKey();
  end;

   // Vendors section
  if hReg.OpenKey(lwzgr_reg_vendors, true) then with hReg do begin
     if ValueExists('vendTermClientPath') then vendTermClientPath := ReadString('vendTermClientPath');
     if ValueExists('vendRadminPath') then vendRadminPath := ReadString('vendRadminPath');
     if ValueExists('vendRadminPort') then vendRadminPort := ReadInteger('vendRadminPort');
     if ValueExists('intKaspersky') then intKaspersky := ReadBool('intKaspersky');
     if ValueExists('intKESOutOfBases') then intKESOutOfBases := ReadInteger('intKESOutOfBases');

     if ValueExists('vendTightVNCViewerPath') then vendTightVNCViewerPath := ReadString('vendTightVNCViewerPath');
     if ValueExists('vendTightVNCServerPath') then vendTightVNCServerPath := ReadString('vendTightVNCServerPath');
     if ValueExists('vendTightVNCPort') then vendTightVNCPort := ReadInteger('vendTightVNCPort');

     if ValueExists('vendUltraVNCViewerPath') then vendUltraVNCViewerPath := ReadString('vendUltraVNCViewerPath');

     if ValueExists('intSCCMDefaultServer') then intSCCMDefaultServer := ReadString('intSCCMDefaultServer');
     if ValueExists('intSMSRemoteToolApp') then intSMSRemoteToolApp := ReadString('intSMSRemoteToolApp');
     if ValueExists('intSMSUseServerName') then intSMSUseServerName := ReadBool('intSMSUseServerName');

     if ValueExists('vendNmapPath') then vendNmapPath := ReadString('vendNmapPath');

     if ValueExists('vendUseDefaultBrowser') then vendUseDefaultBrowser := ReadBool('vendUseDefaultBrowser');
     if ValueExists('vendBrowserPath') then vendBrowserPath := ReadString('vendBrowserPath');
     if ValueExists('VendBrowserAddSearchString') then VendBrowserAddSearchString := ReadString('VendBrowserAddSearchString');
     if ValueExists('vendBrowserUseAddSearchString') then vendBrowserUseAddSearchString := ReadBool('vendBrowserUseAddSearchString');


     CloseKey();
  end;

   // Scan section
  if hReg.OpenKey(lwzgr_reg_scan, true) then with hReg do begin
    if ValueExists('scanThreadCount') then scanThreadCount := ReadInteger('scanThreadCount');
    if ValueExists('scanMethod') then scanMethod := ReadInteger('scanMethod');
    if ValueExists('scanPriotiryBoost') then scanPriotiryBoost := ReadBool('scanPriotiryBoost');
    if ValueExists('scanSaveSpan') then scanSaveSpan := ReadInteger('scanSaveSpan');
    if ValueExists('scanComputerTimeLimit') then scanComputerTimeLimit := ReadInteger('scanComputerTimeLimit');
    if ValueExists('scanFullTimeLimit') then scanFullTimeLimit := ReadInteger('scanFullTimeLimit');

    if ValueExists('scanEvaluateComputers') then scanEvaluateComputers := ReadBool('scanEvaluateComputers');
    if ValueExists('scanSelectProblems') then scanSelectProblems := ReadBool('scanSelectProblems');
    if ValueExists('scanImmediateListSaving') then scanImmediateListSaving := ReadBool('scanImmediateListSaving');
    if ValueExists('scanSkipVisibilityTest') then scanSkipVisibilityTest := ReadBool('scanSkipVisibilityTest');
    if ValueExists('scanUseWMI') then scanUseWMI := ReadBool('scanUseWMI');
    if ValueExists('scanActivateProfiling') then scanActivateProfiling := ReadBool('scanActivateProfiling');
    if ValueExists('scanReadEventlogScan') then scanReadEventlogScan := ReadBool('scanReadEventlogScan');
    if ValueExists('scanReadEventlogQuery') then scanReadEventlogQuery := ReadBool('scanReadEventlogQuery');
    if ValueExists('scanInstallAgentScan') then scanInstallAgentScan := ReadBool('scanInstallAgentScan');
    if ValueExists('scanInstallAgentQuery') then scanInstallAgentQuery := ReadBool('scanInstallAgentQuery');
    if ValueExists('scanIdentifyUser') then scanIdentifyUser := ReadBool('scanIdentifyUser');
    if ValueExists('scanIdentifyUserAlways') then scanIdentifyUserAlways := ReadBool('scanIdentifyUserAlways');

    if ValueExists('scanCheckCompName') then scanCheckCompName := ReadBool('scanCheckCompName');
    if ValueExists('scanCheckInternetSvc') then scanCheckInternetSvc := ReadBool('scanCheckInternetSvc');
    if ValueExists('scanCheckCritUpdates') then scanCheckCritUpdates := ReadBool('scanCheckCritUpdates');

    if ValueExists('scanDeleteShares') then scanDeleteShares := ReadBool('scanDeleteShares');

    if ValueExists('scanEnableBrandmauer') then scanEnableBrandmauer := ReadBool('scanEnableBrandmauer');
    if ValueExists('scanEnableRemRegistry') then scanEnableRemRegistry := ReadBool('scanEnableRemRegistry');
    if ValueExists('scanEnableIndexing') then scanEnableIndexing := ReadBool('scanEnableIndexing');
    if ValueExists('scanDisableCompressionPolicy') then scanDisableCompressionPolicy := ReadInteger('scanDisableCompressionPolicy');
    if ValueExists('scanSrvOnAppStart') then scanSrvOnAppStart := ReadBool('scanSrvOnAppStart');
    if ValueExists('MonEnvOnAppStart') then MonEnvOnAppStart := ReadBool('MonEnvOnAppStart');
    if ValueExists('scanDCOMParams') then scanDCOMParams := ReadBool('scanDCOMParams');

    if ValueExists('scanCleanTempFolders') then scanCleanTempFolders := ReadBool('scanCleanTempFolders');
    if ValueExists('scanCleanBins') then scanCleanBins := ReadBool('scanCleanBins');
    if ValueExists('scanCleanSpoolers') then scanCleanSpoolers := ReadBool('scanCleanSpoolers');

    if ValueExists('scanShowPhysNetAdaptersOnly') then scanShowPhysNetAdaptersOnly := ReadBool('scanShowPhysNetAdaptersOnly');
    if ValueExists('scanGetTasks') then scanGetTasks := ReadBool('scanGetTasks');
    if ValueExists('scanGetSoft') then scanGetSoft := ReadBool('scanGetSoft');
    if ValueExists('scanGetSoftUninstall') then scanGetSoftUninstall := ReadBool('scanGetSoftUninstall');
    if ValueExists('scanGetUpdates') then scanGetUpdates := ReadBool('scanGetUpdates');

    if ValueExists('scanGetSvcDrv') then scanGetSvcDrv := ReadBool('scanGetSvcDrv');
    if ValueExists('scanGetUsrGrp') then scanGetUsrGrp := ReadBool('scanGetUsrGrp');
    if ValueExists('scanControlAdmGroups') then scanControlAdmGroups := ReadBool('scanControlAdmGroups');
    if ValueExists('scanNativeReadEvents') then scanNativeReadEvents := ReadBool('scanNativeReadEvents');
    if ValueExists('scanDoNotExtractEventText') then scanDoNotExtractEventText := ReadBool('scanDoNotExtractEventText');
    if ValueExists('scanFixFakeSessions') then scanFixFakeSessions := ReadBool('scanFixFakeSessions');
    if ValueExists('scanFixWrongDNSNames') then scanFixWrongDNSNames := ReadBool('scanFixWrongDNSNames');
    if ValueExists('scanCheckTempFolders') then scanCheckTempFolders := ReadBool('scanCheckTempFolders');

    if ValueExists('scanCleanAddFolder') then scanCleanAddFolder := ReadBool('scanCleanAddFolder');
    if ValueExists('scanCleanAddService') then scanCleanAddService := ReadBool('scanCleanAddService');
    if ValueExists('scanCreateNetworkList') then scanCreateNetworkList := ReadBool('scanCreateNetworkList');
    if ValueExists('scanUseSpreadLogging') then scanUseSpreadLogging := ReadBool('scanUseSpreadLogging');

    if ValueExists('scana1') then scanacRestartComp := ReadBool('scana1');
    if ValueExists('scana2') then scanacProblemKES := ReadBool('scana2');
    if ValueExists('scana3') then scanacProblemSCCM := ReadBool('scana3');
    if ValueExists('scana4') then scanacProblemWMI := ReadBool('scana4');
    if ValueExists('scana5') then scanacProblemPrintJ := ReadBool('scana5');
    if ValueExists('scana6') then scanacAlive := ReadBool('scana6');
    if ValueExists('scana7') then scanacDisableHibernation := ReadBool('scana7');
    if ValueExists('scana8') then scanacDisableUAC := ReadBool('scana8');
    if ValueExists('scana9') then scanacEnableDCOM := ReadBool('scana9');

    CloseKey();
  end;
   // Accounts section
  if hReg.OpenKey(lwzgr_reg_Account, true) then with hReg do begin
    if ValueExists('accImplicitAccount') then accImplicitAccount := ReadBool('accImplicitAccount');
    if ValueExists('accImplicitAccountAnDom') then accImplicitAccountAnDom := ReadBool('accImplicitAccountAnDom');
    if ValueExists('accUserName') then accUserName := ReadString('accUserName');
    if ValueExists('accUserPassword') then accUserPassword := ReadString('accUserPassword');
    if ValueExists('accUserNameAnDom') then accUserNameAnDom := ReadString('accUserNameAnDom');
    if ValueExists('accUserPasswordAnDom') then accUserPasswordAnDom := ReadString('accUserPasswordAnDom');
    if ValueExists('accUpdateFtpUName') then accUpdateFtpUName := ReadString('accUpdateFtpUName');
    if ValueExists('accUpdateFtpUPassw') then accUpdateFtpUPassw := ReadString('accUpdateFtpUPassw');
    if ValueExists('accAddDomainSuffix') then accAddDomainSuffix := ReadBool('accAddDomainSuffix');
    if ValueExists('accDomainSuffix') then accDomainSuffix := ReadString('accDomainSuffix');

    if ValueExists('prxUse') then prxUse := ReadBool('prxUse');
    if ValueExists('prxServer') then prxServer := ReadString('prxServer');
    if ValueExists('prxUser') then prxUser := ReadString('prxUser');
    if ValueExists('prxPassword') then prxPassword := ReadString('prxPassword');
  end;

   // Alert Criteria
  if hReg.OpenKey(lwzgr_reg_alert, true) then with hReg do begin
    if ValueExists('critSlowChannel') then critSlowChannel := ReadInteger('critSlowChannel');
    if ValueExists('critNotEnoughtDiskSpace') then critNotEnoughtDiskSpace := ReadInteger('critNotEnoughtDiskSpace');
    if ValueExists('critOSInstalledYearsAgo') then critOSInstalledYearsAgo := ReadInteger('critOSInstalledYearsAgo');
    if ValueExists('critWSUSDoesNotWork') then critWSUSDoesNotWork := ReadInteger('critWSUSDoesNotWork');
    if ValueExists('critCompDoesNotRestart') then critCompDoesNotRestart := ReadInteger('critCompDoesNotRestart');
    if ValueExists('critTimeDifference') then critTimeDifference := ReadInteger('critTimeDifference');
    if ValueExists('critRAMSize') then critRAMSize := ReadInteger('critRAMSize');
    if ValueExists('critPwdAgeDays') then critPwdAgeDays := ReadInteger('critPwdAgeDays');
    if ValueExists('critCodePage') then critCodePage := ReadString('critCodePage');

    if ValueExists('critRestartText') then critRestartText := ReadString('critRestartText');
    if ValueExists('critRestartDelay') then critRestartDelay := ReadInteger('critRestartDelay');

   CloseKey();
  end;
   // Routers
  if hReg.OpenKey(lwzgr_reg_Routers, true) then with hReg do begin
   if ValueExists('snmpCommunityString') then snmpCommunityString := ReadString('snmpCommunityString');
   if ValueExists('snmpGetRouteTable') then snmpGetRouteTable := ReadBool('snmpGetRouteTable');
   if ValueExists('snmpRefreshInterval') then snmpRefreshInterval := ReadInteger('snmpRefreshInterval');

    CloseKey();
  end;

  glb_TermClientPresent      := FileExists(vendTermClientPath);
  glb_RadminPresent          := FileExists(vendRadminPath);
  glb_TightVNCViewerPresent  := FileExists(vendTightVNCViewerPath);
  glb_TightVNCServerPresent  := FileExists(vendTightVNCServerPath);
  glb_SMSRemoteToolPresent   := FileExists(intSMSRemoteToolApp);

  vendTightVNCHooksPath  := ExtractFilePath(vendTightVNCServerPath) +  '\screenhooks32.dll';
  DP.designNoBorders := appNoBorders;
  DP.designDrawListLines := appDrawListLines;
  gfCustomizeLocalRedistrPath();
 finally
  FreeAndNil(hReg);
 end;
 gfDecryptSecrets();
end;
// *******************************************************************
//  gfSettingsWrite
// *******************************************************************
procedure gfSettingsWrite;
var
  hReg: TRegistry;
begin
 gfEncryptSecrets();
 hReg := TRegistry.Create();

 try
  hReg.RootKey := HKEY_CURRENT_USER;
  if hReg.OpenKey(CLRegPath, true) then with hReg do begin

   WriteInteger('appLocale', appLocale);

   WriteInteger('appRunCount', appRunCount + 1);
   WriteInteger('appLProfilePolicy', appLProfilePolicy);
   WriteInteger('appBottomPanelHeight', appBottomPanelHeight);
   WriteBool('appMinimizeToTray', appMinimizeToTray);
   WriteBool('appAutoClipboard', appAutoClipboard);
   WriteBool('appColorizeItems', appColorizeItems);
   WriteBool('appNoHidePassw', appNoHidePassw);
   WriteBool('appNoBorders', appNoBorders);
   WriteBool('appDrawListLines', appDrawListLines);
   WriteBool('appShowButtonText', appShowButtonText);

   WriteInteger('appFontSize', appFontSize);
   WriteBool('appSrvGroupView', appSrvGroupView);

   WriteBool('appStopMonitorOnFailKESState', appStopMonitorOnFailKESState);
   WriteBool('appStartMonitorOnGoodKESState', appStartMonitorOnGoodKESState);
   WriteString('appHostsFile', appHostsFile);

   WriteBool('appResolveIpAddresses', appResolveIpAddresses);
   WriteBool('appResolveIpAddressesFlt', appResolveIpAddressesFlt);
   WriteBool('appResolveComputerNames', appResolveComputerNames);
   WriteBool('appAddResolvedOnly', appAddResolvedOnly);
   WriteString('appRedistrFolderPath', appRedistrFolderPath);

   WriteBool('appLoadLastList', appLoadLastList);
   WriteBool('appShowAssistant', appShowAssistant);

   WriteBool('appUseUpdate' , appUseUpdate);
   WriteString('appUpdateSource' , appUpdateSource);
   WriteInteger('appNmapIndex', appNmapIndex);

   WriteBool('appAnotherDomModeEnabled' , appAnotherDomModeEnabled);
   WriteString('appAnotherDomName' , appAnotherDomName);

   CloseKey();
  end;
   // Parameters section
  if hReg.OpenKey(lwzgr_reg_Parameters, true) then with hReg do begin
    WriteInteger('parConnectMethod', parConnectMethod);

  end;
  // Vendors
  if hReg.OpenKey(lwzgr_reg_vendors, true) then with hReg do begin
   WriteString('vendTermClientPath', vendTermClientPath);
   WriteString('vendRadminPath', vendRadminPath);
   WriteInteger('vendRadminPort', vendRadminPort);

   WriteString('vendTightVNCViewerPath', vendTightVNCViewerPath);
   WriteString('vendTightVNCServerPath', vendTightVNCServerPath);
   WriteInteger('vendTightVNCPort', vendTightVNCPort);

   WriteString('vendUltraVNCViewerPath', vendUltraVNCViewerPath);

   WriteString('intSCCMDefaultServer', intSCCMDefaultServer);
   WriteString('intSMSRemoteToolApp', intSMSRemoteToolApp);
   WriteBool('intSMSUseServerName', intSMSUseServerName);

   WriteString('vendNmapPath', vendNmapPath);
   WriteBool('intKaspersky', intKaspersky);
   WriteInteger('intKESOutOfBases', intKESOutOfBases);

   WriteBool('vendUseDefaultBrowser', vendUseDefaultBrowser);
   WriteString('vendBrowserPath', vendBrowserPath);
   WriteString('VendBrowserAddSearchString', VendBrowserAddSearchString);
   WriteBool('vendBrowserUseAddSearchString', vendBrowserUseAddSearchString);

   CloseKey();
  end;
  // Scan
  if hReg.OpenKey(lwzgr_reg_scan, true) then with hReg do begin
   WriteInteger('scanThreadCount', scanThreadCount);
   WriteInteger('scanMethod', scanMethod);
   WriteBool('scanPriotiryBoost', scanPriotiryBoost);
   WriteInteger('scanSaveSpan', scanSaveSpan);
   WriteInteger('scanComputerTimeLimit', scanComputerTimeLimit);
   WriteInteger('scanFullTimeLimit', scanFullTimeLimit);

   WriteBool('scanEvaluateComputers', scanEvaluateComputers);
   WriteBool('scanSelectProblems', scanSelectProblems);
   WriteBool('scanImmediateListSaving', scanImmediateListSaving);
   WriteBool('scanSkipVisibilityTest', scanSkipVisibilityTest);
   WriteBool('scanUseWMI', scanUseWMI);
   WriteBool('scanActivateProfiling', scanActivateProfiling);
   WriteBool('scanReadEventlogScan', scanReadEventlogScan);
   WriteBool('scanReadEventlogQuery', scanReadEventlogQuery);
   WriteBool('scanInstallAgentScan', scanInstallAgentScan);
   WriteBool('scanInstallAgentQuery', scanInstallAgentQuery);
   WriteBool('scanIdentifyUser', scanIdentifyUser);
   WriteBool('scanIdentifyUserAlways', scanIdentifyUserAlways);
   WriteBool('scanCheckCompName', scanCheckCompName);
   WriteBool('scanCheckInternetSvc', scanCheckInternetSvc);
   WriteBool('scanCheckCritUpdates', scanCheckCritUpdates);

   WriteBool('scanDeleteShares', scanDeleteShares);
   WriteBool('scanEnableBrandmauer', scanEnableBrandmauer);
   WriteBool('scanEnableRemRegistry', scanEnableRemRegistry);
   WriteBool('scanEnableIndexing', scanEnableIndexing);
   WriteBool('scanDCOMParams', scanDCOMParams);

   WriteInteger('scanDisableCompressionPolicy', scanDisableCompressionPolicy);
   WriteBool('scanSrvOnAppStart', scanSrvOnAppStart);
   WriteBool('MonEnvOnAppStart', MonEnvOnAppStart);

   WriteBool('scanCleanTempFolders', scanCleanTempFolders);
   WriteBool('scanCleanBins', scanCleanBins);
   WriteBool('scanCleanSpoolers', scanCleanSpoolers);

   WriteBool('scanShowPhysNetAdaptersOnly', scanShowPhysNetAdaptersOnly);
   WriteBool('scanGetTasks', scanGetTasks);
   WriteBool('scanGetSoft', scanGetSoft);
   WriteBool('scanGetSoftUninstall', scanGetSoftUninstall);

   WriteBool('scanGetUpdates', scanGetUpdates);
   WriteBool('scanGetSvcDrv', scanGetSvcDrv);
   WriteBool('scanGetUsrGrp', scanGetUsrGrp);
   WriteBool('scanControlAdmGroups', scanControlAdmGroups);
   WriteBool('scanNativeReadEvents', scanNativeReadEvents);
   WriteBool('scanDoNotExtractEventText', scanDoNotExtractEventText);
   WriteBool('scanFixFakeSessions', scanFixFakeSessions);
   WriteBool('scanFixWrongDNSNames', scanFixWrongDNSNames);
   WriteBool('scanCheckTempFolders', scanCheckTempFolders);

   WriteBool('scanCleanAddFolder', scanCleanAddFolder);
   WriteBool('scanCleanAddService', scanCleanAddService);
   WriteBool('scanCreateNetworkList', scanCreateNetworkList);
   WriteBool('scanUseSpreadLogging', scanUseSpreadLogging);

   WriteBool('scana1', scanacRestartComp);
   WriteBool('scana2', scanacProblemKES);
   WriteBool('scana3', scanacProblemSCCM);
   WriteBool('scana4', scanacProblemWMI);
   WriteBool('scana5', scanacProblemPrintJ);
   WriteBool('scana6', scanacAlive);
   WriteBool('scana7', scanacDisableHibernation);
   WriteBool('scana8', scanacDisableUAC);
   WriteBool('scana9', scanacEnableDCOM);

   CloseKey();
  end;
   // Alert Criteria
  if hReg.OpenKey(lwzgr_reg_Alert, true) then with hReg do begin
   WriteInteger('critSlowChannel', critSlowChannel);
   WriteInteger('critNotEnoughtDiskSpace', critNotEnoughtDiskSpace);
   WriteInteger('critOSInstalledYearsAgo', critOSInstalledYearsAgo);
   WriteInteger('critWSUSDoesNotWork', critWSUSDoesNotWork);
   WriteInteger('critCompDoesNotRestart', critCompDoesNotRestart);
   WriteInteger('critTimeDifference', critTimeDifference);
   WriteInteger('critRAMSize', critRAMSize);
   WriteInteger('critPwdAgeDays', critPwdAgeDays);
   WriteString('critCodePage', critCodePage);

   WriteString('critRestartText', critRestartText);
   WriteInteger('critRestartDelay', critRestartDelay);
  end;

  if hReg.OpenKey(lwzgr_reg_Account, true) then with hReg do begin
    WriteBool('accImplicitAccount', accImplicitAccount);
    WriteBool('accImplicitAccountAnDom', accImplicitAccountAnDom);
    WriteString('accUserName', accUserName);
    WriteString('accUserPassword', accUserPassword);
    WriteString('accUserNameAnDom', accUserNameAnDom);
    WriteString('accUserPasswordAnDom', accUserPasswordAnDom);

    WriteBool('prxUse', prxUse);
    WriteString('prxServer', prxServer);
    WriteString('prxUser', prxUser);
    WriteString('prxPassword', prxPassword);

    WriteString('accUpdateFtpUPassw', accUpdateFtpUPassw);
    WriteString('accUpdateFtpUName', accUpdateFtpUName);

    WriteBool('accAddDomainSuffix', accAddDomainSuffix);
    WriteString('accDomainSuffix', accDomainSuffix);

  end;

  if hReg.OpenKey(lwzgr_reg_Routers, true) then with hReg do begin
    WriteString('snmpCommunityString', snmpCommunityString);
    WriteBool('snmpGetRouteTable', snmpGetRouteTable);
    WriteInteger('snmpRefreshInterval', snmpRefreshInterval);
  end;

 DP.designNoBorders := appNoBorders;
 DP.designDrawListLines := appDrawListLines;

 finally
  FreeAndNil(hReg);
 end;
end;
// ***************************************************************
// gfUnionOptRead
// ***************************************************************
procedure gfUnionOptRead(var UO : TReportUnion);
var
 hReg: TRegistry;
begin
 hReg := TRegistry.Create();

 try
  hReg.RootKey := HKEY_CURRENT_USER;
  if hReg.OpenKey(CLRegPathUO, true) then with hReg do begin

    if ValueExists('ruADComp') then UO.ruADComp := ReadBool('ruADComp');
    if ValueExists('ruADUser') then UO.ruADUser := ReadBool('ruADUser');
    if ValueExists('ruSessions') then UO.ruSessions := ReadBool('ruSessions');
    if ValueExists('ruLogicalDrive') then UO.ruLogicalDrive := ReadBool('ruLogicalDrive');
    if ValueExists('ruDiskSystem') then UO.ruDiskSystem := ReadBool('ruDiskSystem');
    if ValueExists('ruHardware') then UO.ruHardware := ReadBool('ruHardware');
    if ValueExists('ruPrinters') then UO.ruPrinters := ReadBool('ruPrinters');
    if ValueExists('ruNetworkParam') then UO.ruNetworkParam := ReadBool('ruNetworkParam');
    if ValueExists('ruSoftware') then UO.ruSoftware := ReadBool('ruSoftware');
    if ValueExists('ruUpdates') then UO.ruUpdates := ReadBool('ruUpdates');
    if ValueExists('ruEnvVar') then UO.ruEnvVar := ReadBool('ruEnvVar');
    if ValueExists('ruProcesses') then UO.ruProcesses := ReadBool('ruProcesses');
    if ValueExists('ruServices') then UO.ruServices := ReadBool('ruServices');
    if ValueExists('ruConnections') then UO.ruConnections := ReadBool('ruConnections');
    if ValueExists('ruUsers') then UO.ruUsers := ReadBool('ruUsers');
    if ValueExists('ruEvents') then UO.ruEvents := ReadBool('ruEvents');
  end;
 finally
   FreeAndNil(hReg);
 end;
end;
// ***************************************************************
// gfUnionOptWrite
// ***************************************************************
procedure gfUnionOptWrite(UO : TReportUnion);
var
 hReg: TRegistry;
begin
 hReg := TRegistry.Create();

 try
  hReg.RootKey := HKEY_CURRENT_USER;
  if hReg.OpenKey(CLRegPathUO, true) then with hReg do begin

    WriteBool('ruADComp', UO.ruADComp);
    WriteBool('ruADUser', UO.ruADUser);
    WriteBool('ruSessions', UO.ruSessions);
    WriteBool('ruLogicalDrive', UO.ruLogicalDrive);
    WriteBool('ruDiskSystem', UO.ruDiskSystem);
    WriteBool('ruHardware', UO.ruHardware);
    WriteBool('ruPrinters', UO.ruPrinters);
    WriteBool('ruNetworkParam', UO.ruNetworkParam);
    WriteBool('ruSoftware', UO.ruSoftware);
    WriteBool('ruUpdates', UO.ruUpdates);
    WriteBool('ruEnvVar', UO.ruEnvVar);
    WriteBool('ruProcesses', UO.ruProcesses);
    WriteBool('ruServices', UO.ruServices);
    WriteBool('ruConnections', UO.ruConnections);
    WriteBool('ruUsers', UO.ruUsers);
    WriteBool('ruEvents', UO.ruEvents);
  end;
 finally
   FreeAndNil(hReg);
 end;
end;
// ***************************************************************
// Construct needed path on fly
// Ending backslash assumed for eny directory name
// ***************************************************************
procedure gfAppUpdateDirs;
var
 PublicDir : String;
 dwError   : DWORD;
begin
  glb_PathExe := ExtractFileDir(ExtractFilePath(Application.ExeName)) + '\';
  glb_PathUtils := glb_PathExe + 'Utils';
  if not glbPortableBehaviour then begin
   gfGetAppDataDir();
   if (glb_PathAppData = LC_EMPTY_STRING) then
       glb_PathAppData := glb_PathExe;

   gfCheckAndCreateDir(glb_PathAppData);
  end else
   glb_PathAppData := glb_PathExe;

  glbSpreadLogMessageFile := glb_PathExe + '\' + SPREAD_LOG_MSGDLL;
  if FileExists(glbSpreadLogMessageFile) then
   glb_SpreadLogVerStr := lwGetStringVersion(glbSpreadLogMessageFile);


  glb_PathCompLists     := glb_PathAppData + '\' + CL_PATH_CompLists;
  glb_PathCopmListsFxF  := glb_PathCompLists + '\' + CL_PATH_FilPerFil;
  glb_PathCopmListsCS   := glb_PathCompLists + '\' + CL_PATH_CORP_SYS + '\';
  glb_PathCopmListsNetw := glb_PathCompLists + '\' + CL_PATH_Networks;
  glb_PathReports    := glb_PathAppData + '\' + CL_PATH_Reports;
  glb_PathReportsComp := glb_PathReports + '\' + 'Computers';
  glb_PathTemp       := glb_PathAppData + '\Temp';
  glb_PathDebug      := glb_PathAppData + '\Debug';
  glb_PathFilters    := glb_PathAppData + '\' + CL_PATH_Filters;
  glb_PathRepSess    := glb_PathAppData + '\' + CL_PATH_SCANSESS;
  glb_PathTemplates  := glb_PathAppData + '\' + CL_PATH_TEMPLATES;
  glb_PathEnvHistory := glb_PathAppData + '\' + CL_PATH_ENV_HIST;
  glb_PathSMSAdminUI := sys2GetSMSAdmUIDirectory();
  if (glb_PathSMSAdminUI = LC_EMPTY_STRING) then
    glb_PathSMSAdminUI := glb_PathUtils;

  glb_PathPowerShell := glb_PathAppData + '\PS\';

  glb_ServerConfigFile := glb_PathCompLists + '\' + srvCfgFileName;

  gfCheckAndCreateDir(glb_PathCompLists);
  gfCheckAndCreateDir(glb_PathCopmListsFxF);
  gfCheckAndCreateDir(glb_PathCopmListsCS);
  gfCheckAndCreateDir(glb_PathCopmListsNetw);
  gfCheckAndCreateDir(glb_PathReports);
  gfCheckAndCreateDir(glb_PathReportsComp);
  gfCheckAndCreateDir(glb_PathTemp);
  gfCheckAndCreateDir(glb_PathDebug);
  gfCheckAndCreateDir(glb_PathUpdate);
  gfCheckAndCreateDir(glb_PathFilters);
  gfCheckAndCreateDir(glb_PathRepSess);
  gfCheckAndCreateDir(glb_PathTemplates);
  gfCheckAndCreateDir(glb_PathEnvHistory);
  gfCheckAndCreateDir(glb_PathPowerShell);

  glb_DefaultHostsFile := glb_PathCompLists + '\' + cfgDefaultFile;
  glbSrvFile           := glb_PathFilters + '\' + SrvFile;
  glbADFilterFile      := glb_PathFilters + '\' + ADFltFile;
  glbNetworkFilterFile := glb_PathFilters + '\' + NetwFltFile;

  glbAppLogFile   := glb_PathAppData + '\'+ AppLogFile;
  glbLdapLogFile  := glb_PathAppData + '\'+ LdapLog;

  glbCNamesGeoFile := glb_PathTemplates + '\' + cNameGeo;
  glbCNamesOrgFile := glb_PathTemplates + '\' + cNameOrg;

  if FileExists(glbCNamesGeoFile) and FileExists(glbCNamesOrgFile) then begin
   glb_CompNamesGeo := TStringList.Create();
   glb_CompNamesOrg := TStringList.Create();

   glb_CompNamesGeo.LoadFromFile(glbCNamesGeoFile);
   glb_CompNamesOrg.LoadFromFile(glbCNamesOrgFile);
 end;

  glbNmapCommands   := glb_PathTemplates + '\' + nmapTemplates;
  {$IFDEF DEBUG_VER}
   glbDBLibrary   := 'C:\Develop\LanWeatherCARMA\DB\Win32\Debug\crmdbhlp.dll';
   glbPackLibrary := 'C:\Develop\LanWeatherCARMA\ADDZipper\Win32\Debug\crmpacker.dll';
   dbgScan := TDebugSection.Create(glb_PathTemp);

  {$ELSE}
    glbDBLibrary   := 'crmdbhlp.dll';
    glbPackLibrary := 'crmpacker.dll';
  {$ENDIF}

  glb_CNameTemplatesPresent := FileExists(glbCNamesGeoFile) and FileExists(glbCNamesOrgFile);

  {$IFNDEF AGENT_TEST_LOCAL}
    glb_AgentExe := glb_PathExe + AgentExe;
    glb_AgentPresent := FileExists(glb_AgentExe);
    if glb_AgentPresent then
     glb_AgentVerStr := lwGetStringVersion(glb_AgentExe);
  {$ELSE}
    glb_AgentPresent := true;
  {$ENDIF}

  glb_HelpFile := glb_PathExe + 'Carma.pdf';

  glb_MessengerExe := glb_PathExe + MessengerExe;
  glb_MessengerPresent := FileExists(glb_MessengerExe);
  if glb_MessengerPresent then
   glb_MessengerVerStr := lwGetStringVersion(glb_MessengerExe);

  glb_PaExeFile := glb_PathExe + 'PAexec.exe';
  glb_PsExeFile := glb_PathExe + 'PSexec.exe';

  glb_MMC_Runner := glb_SysPaths.rsSysDir + '\mmc.exe';

  glb_Rexec_Storage  := glb_PathTemplates  + '\' + 'app.rex';
  glb_CE_Storage     := glb_PathTemplates  + '\' + 'app.ce';
  glb_WKGr_Storage   := glb_PathTemplates  + '\' + 'app.gr';
  glb_Utils_Storage  := glb_PathTemplates  + '\' + 'app.ut';
  glb_BitAct_Storage := glb_PathTemplates  + '\' + 'app.bia';
  glb_Report_Storage := glb_PathTemplates  + '\' + 'app.rep';
  glb_Env_Storage    := glb_PathEnvHistory + '\' + 'env.hst';
  glb_DCOMFav_Storage:= glb_PathEnvHistory + '\' + 'dcom.fav';

end;
// ***************************************************************
// gfCustomizeLocalRedistrPath
// ***************************************************************
procedure gfCustomizeLocalRedistrPath;
begin
 if not DirectoryExists(appRedistrFolderPath) then begin
   appRedistrFolderPath := glb_PathAppData + '\' + CL_PATH_REDISTR;
   gfCheckAndCreateDir(appRedistrFolderPath);
 end;
end;
// ***************************************************************
// gfSendMessageToGUI
// ***************************************************************
procedure gfSendMessageToGUI(Msg: String);
begin
  SendMessage(glb_AppMainWndHandle, MESS_WND_CATCH_TEXT, 0, LPARAM(Msg));
end;
// ***************************************************************
// gfInputString
// ***************************************************************
function  gfInputString(const aCaption,aPrompt,aText : String) : String;
begin
  with TFrmInputDialog.Create(nil) do begin
    Caption := aCaption;
    GroupBoxInput.Caption := ' ' + aPrompt + ' ';
    edtText.Text := aText;
    ShowModal();
   if (ModalResult = mrOk) then
    result := edtText.Text;
   Free();
  end;
end;
// *****************************************************************************************
// lddDomainNameToLdapName
// *****************************************************************************************
function lwldapDomainNameToLdapName(dname : String) : String;
var
 _i : Integer;
begin
 result := '';
 if (Pos('.', dname) = 0) or (Pos('.', dname) = 1) then exit;
 result := 'DC=';
 for _i := 1 to Length(dname)  do begin
   if (dname[_i] <> '.') then
    result := result + dname[_i] else
     result := result + ',DC=';
 end;
end;
// *****************************************************************************
// gfModifyTrusteeNameWithSuffix
// *****************************************************************************
function  gfModifyTrusteeNameWithSuffix(const Trustee : String) : String;
var
 lUserName, lDomainName : String;
begin
 if (Pos(accDomainSuffix, Trustee) > 0) or
    (not luSplitUsersDomain(Trustee, lDomainName, lUserName) ) then
      result := Trustee else
        result := lDomainName + '.' + accDomainSuffix + '\' + lUserName;
end;
// *****************************************************************************
// gfShareNameIsReserved
// *****************************************************************************
function gfShareNameIsReserved(sName : String) : boolean;
var
 i : Integer;
begin
 result := false;
 for i:= 0 to High(AResShareNames) do begin
  if (Pos(Trim(AnsiUpperCase(AResShareNames[i])), Trim(AnsiUpperCase(sName))) > 0) then begin
    result := true;
    break;
  end;
 end;
end;
// *****************************************************************************
// gfWow64DisableRedirection
// *****************************************************************************
procedure gfWow64DisableRedirection(var EnableRedirection: boolean);
var
  Wow64FsEnableRedirection: LongBool;
begin
  if glb_RedirectLoaded then  begin
    Wow64FsEnableRedirection := EnableRedirection;
    Wow64DisableWow64FsRedirection(Wow64FsEnableRedirection);
    EnableRedirection := Wow64FsEnableRedirection;
  end else
    EnableRedirection := False;
end;
// *****************************************************************************
// gfWow64EnableRedirection
// *****************************************************************************
procedure gfWow64EnableRedirection(var EnableRedirection: boolean);
var
  Wow64FsEnableRedirection: LongBool;
begin
  if glb_RedirectLoaded then begin
    Wow64FsEnableRedirection := EnableRedirection;
    Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection);
    EnableRedirection := Wow64FsEnableRedirection;
  end else
    EnableRedirection := False;
end;
// *****************************************************************************
// gfRedirectLoad
// *****************************************************************************
function gfRedirectLoad: boolean;
var H: HModule;
begin
  if not glb_RedirectLoaded then  begin
    H := GetModuleHandle('kernel32.dll');
    if (H <> 0) then  begin
      @Wow64EnableWow64FsRedirection := GetProcAddress(H, 'Wow64EnableWow64FsRedirection');
      @Wow64DisableWow64FsRedirection := GetProcAddress(H, 'Wow64DisableWow64FsRedirection');
    end else begin
      @Wow64EnableWow64FsRedirection := nil;
      @Wow64DisableWow64FsRedirection := nil;
    end;
    glb_RedirectLoaded := True;
  end;
  Result := (@Wow64EnableWow64FsRedirection <> nil) and
            (@Wow64DisableWow64FsRedirection <> nil);
end;
// ***************************************************************
// gfEncryptSecrets
// ***************************************************************
procedure gfEncryptSecrets;
begin
  // Domain account
  if (glb_DecryptedUserName <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      accUserName := crStringEncrypt(glb_DecryptedUserName, cfgConfigKeyPhrase)  else
       accUserName := glb_DecryptedUserName;
    end;
  if (glb_DecryptedUserPassw <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      accUserPassword := crStringEncrypt(glb_DecryptedUserPassw,cfgConfigKeyPhrase) else
        accUserPassword := glb_DecryptedUserPassw;
    end;

  // Domain account ANOTHER DOMAIN
  if (glb_DecryptedUserNameAnDom <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      accUserNameAnDom := crStringEncrypt(glb_DecryptedUserNameAnDom, cfgConfigKeyPhrase)  else
       accUserNameAnDom := glb_DecryptedUserNameAnDom;
    end;
  if (glb_DecryptedUserPasswAnDom <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      accUserPasswordAnDom := crStringEncrypt(glb_DecryptedUserPasswAnDom,cfgConfigKeyPhrase) else
        accUserPasswordAnDom := glb_DecryptedUserPasswAnDom;
    end;
end;
// ***************************************************************
// gfDecryptSecrets
// ***************************************************************
procedure gfDecryptSecrets;
begin
  // Domain accaunt
 if (accUserName <> LC_EMPTY_STRING) then begin
   if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
     glb_DecryptedUserName := crStringDecrypt(accUserName, cfgConfigKeyPhrase) else
      glb_DecryptedUserName := accUserName;
  end;
  if (accUserPassword <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      glb_DecryptedUserPassw := crStringDecrypt(accUserPassword, cfgConfigKeyPhrase)
    else
      glb_DecryptedUserPassw := accUserPassword;
  end;
  // Domain accaunt ANOTHER DOMAIN
 if (accUserNameAnDom <> LC_EMPTY_STRING) then begin
   if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
     glb_DecryptedUserNameAnDom := crStringDecrypt(accUserNameAnDom, cfgConfigKeyPhrase) else
      glb_DecryptedUserNameAnDom := accUserNameAnDom;
  end;
  if (accUserPassword <> LC_EMPTY_STRING) then begin
    if (cfgConfigKeyPhrase <> LC_EMPTY_STRING) then
      glb_DecryptedUserPasswAnDom := crStringDecrypt(accUserPasswordAnDom, cfgConfigKeyPhrase)
    else
      glb_DecryptedUserPasswAnDom := accUserPasswordAnDom;
  end;
end;
// ***************************************************************
// gfDecryptSecrets
// ***************************************************************
procedure gfScanGetOptions(var SO : TScanOptionsShapshot; SelectAll : boolean = false);
begin
 ZeroMemory(@SO , SizeOf(TScanOptionsShapshot));
 if not SelectAll then begin
  SO.so_scanUseWMI := scanUseWMI;
  SO.so_scanUseSpreadLog := scanUseSpreadLogging;
  SO.so_scanActivateProfiling := scanActivateProfiling;
  SO.so_scanIdentifyUser := scanIdentifyUser;
  SO.so_scanIdentifyUserAlways := scanIdentifyUserAlways;
  SO.so_scanCleanTempFolders := scanCleanTempFolders;
  SO.so_scanCleanBins := scanCleanBins;
  SO.so_scanCleanAddFolder := scanCleanAddFolder;
  SO.so_scanCleanAddService := scanCleanAddService;
  SO.so_WMI_ShowPhysNetAdaptersOnly := scanShowPhysNetAdaptersOnly;
  SO.so_scanImmediatellySaving := scanImmediateListSaving;
  SO.so_DisableUAC := scanacDisableUAC;
  SO.so_DisableHibernation := scanacDisableHibernation;
  SO.so_scanEnableBrandmauer := scanEnableBrandmauer;
  SO.so_scanEnableRemRegistry := scanEnableRemRegistry;
  SO.so_ActionRestart := scanacRestartComp;
  SO.so_scanReadEventlogQuery := scanReadEventlogQuery;
  SO.so_scanReadEventlogScan := scanReadEventlogScan;
  SO.so_scanEventLogByWMI := not scanNativeReadEvents;
  SO.so_scanEventLogExtractText := not scanDoNotExtractEventText;
  SO.so_scanGetTasks := scanGetTasks;
  SO.so_scanGetSoftMSI := scanGetSoft;
  SO.so_scanGetSoftUninstall := scanGetSoftUninstall;
  SO.so_scanGetWinUpdates := scanGetUpdates;
  SO.so_scanDCOMParams := scanDCOMParams;
  SO.so_scanGetSvcDrv := scanGetSvcDrv;
  SO.so_scanGetUsrGrp := scanGetUsrGrp;
  SO.so_scanControlAdmGroups := scanControlAdmGroups;
  SO.so_ScanCompressionPolicy := scanDisableCompressionPolicy;
  SO.so_ScanEnableDriveIndexing := scanEnableIndexing;
  SO.so_scanCheckInternetSvc := scanCheckInternetSvc;
  SO.so_scanCheckCritUpdates := scanCheckCritUpdates;
  SO.so_scanFixFakeSessions := scanFixFakeSessions;
  SO.so_scanFixWrongDNSNames := scanFixWrongDNSNames;
  SO.so_scanCheckTempFilders := scanCheckTempFolders;
 end else begin
  SO.so_scanUseWMI := true;
  SO.so_scanIdentifyUser := true;
  SO.so_scanIdentifyUserAlways := false;
  SO.so_scanCleanTempFolders := true;
  SO.so_scanCleanBins := false;
  SO.so_WMI_ShowPhysNetAdaptersOnly := false;
  SO.so_ActionRestart := false;
 end;
end;
// *******************************************************************
//   gfPlaySystemSound
// *******************************************************************
procedure gfPlaySystemSound(FileName : String);
var
 FullFileName : String;
begin
if DirectoryExists(glb_PathSystemSounds) then begin
 FullFileName := glb_PathSystemSounds + '\' + FileName;
 if FileExists(FullFileName) then
   sndPlaySound(PChar(FullFileName), SND_SYNC or SND_NODEFAULT);
end;
end;
// *******************************************************************
//   gfOpenURL
// *******************************************************************
procedure gfOpenURL(URL : String);
var
 nResult : NativeInt;
 S :String;
begin
 if not FileExists(vendBrowserPath) then
  nResult := ShellExecute(0, PChar('open'), PChar(URL), nil, nil, SW_SHOWNORMAL) else
   nResult := ShellExecute(0, PChar('open'), PChar(vendBrowserPath), PChar(URL), nil, SW_SHOWNORMAL);
  S := ifThen((nResult <= 32), format(COMMON_ERR,
             [luGetShelExecResultStr(nResult)]),
             COMMON_SUCC);
  gfSendMessageToGUI(S);
end;
{ TMruList }
{$REGION MRU}
// *******************************************************************
//   Constructor
// *******************************************************************
constructor TMruList.Create(const RegPath: String; Capacity: Integer);
begin
 FFileList := TStringList.Create();
 FRegPath := RegPath;
 FCapacity := Capacity;
 FCount := 0;
end;
// *******************************************************************
//   Destructor
// *******************************************************************
destructor TMruList.Destroy;
begin
 FreeAndNil(FFileList);
 inherited;
end;
// *******************************************************************
//   Load
// *******************************************************************
function TMruList.Load: String;
var
 hReg : TRegistry;
 slValues : TStringList;
 i : Integer;
 sValue : String;
begin
 hReg := TRegistry.Create;
 slValues := TStringList.Create();
 try
  try
   hReg.RootKey := HKEY_CURRENT_USER;
    if hReg.OpenKey(FRegPath, true) then begin
     hReg.GetValueNames(slValues);
     for i := 0 to slValues.Count - 1 do begin
      if hReg.ValueExists(slValues[i]) then begin
       sValue := hReg.ReadString(slValues[i]);
       if FileExists(sValue) then
        FFileList.Add(sValue);
      end;
     end;
    end;
    FCount := FFileList.Count;
   except
    On E: Exception do
     result := E.Message;
   end;
 finally
  FreeAndNil(hReg);
  FreeAndNil(slValues);
 end;
end;
// *******************************************************************
//   Save
// *******************************************************************
function TMruList.Save: String;
var
 hReg : TRegistry;
 i : Integer;
begin
 hReg := TRegistry.Create;
 try
  try
   hReg.RootKey := HKEY_CURRENT_USER;
   if hReg.KeyExists(FRegPath) then
    hReg.DeleteKey(FRegPath);
   hReg.OpenKey(FRegPath, true);
   for i := 0 to FFileList.Count - 1 do begin
    hReg.WriteString('MRU' + IntToStr(i), FFileList[i]);
   end;
  except
    On E: Exception do
     result := E.Message;
  end;
 finally
  FreeAndNil(hReg);
 end;
end;
// *******************************************************************
//   FileExists
// *******************************************************************
function TMruList.ItemExists(const FileName: String): Integer;
var
 i : Integer;
begin
 result := -1;
 for i := 0 to FFileList.Count - 1 do begin
  if FFileList[i] = FileName then begin
   result := i;
   break;
  end;
 end;
end;
// *******************************************************************
//   FileInsert
// *******************************************************************
procedure TMruList.ItemAdd(const FileName: String);
var
 mruIndex : Integer;
begin
 mruIndex := ItemExists(FileName);
 if (mruIndex = -1) then begin
  if (FFileList.Count < FCapacity) then
   FFileList.Add(FileName) else begin
     Shift();
     FFileList[FCapacity - 1] := FileName;
   end;
//  Rotate();
  Save();
 end;
// MakeTopAsSecond();
 FCount := FFileList.Count;
end;
// *******************************************************************
//   Shift
// *******************************************************************
procedure TMruList.Shift;
var
 i : Integer;
begin
 for i := 1 to FCapacity -1 do
  FFileList[i-1] := FFileList[i];
end;
// *******************************************************************
//   Rotate
// *******************************************************************
procedure TMruList.Rotate;
var
 TempList : TStringList;
 i : Integer;
begin
 try
   TempList := TStringList.Create();
   for i := 0 to FFileList.Count -1 do
    TempList.Add('');
   for i := 0 to TempList.Count -1 do
    TempList[i] := FFileList[FFileList.Count -1];

   FFileList.Assign(TempList);
   MakeTopAsSecond();
 finally
   FreeAndNil(TempList);
 end;
end;
// *******************************************************************
//   MakeCurrentAsSecind
// *******************************************************************
procedure TMruList.MakeTopAsSecond;
var
 TempStr : String;
begin
 if (FFileList.Count > 1) then begin
 Tempstr := FFileList[0];
 FFileList[0] := FFileList[1];
 FFileList[1] := TempStr;
 end;

end;
// *******************************************************************
//   gfEventLogNeeds
// *******************************************************************
function  gfEventLogNeeds(ELName : String) : boolean;
var
 i : Integer;
begin
 result := false;
 for i := 0 to High(AEvlErrors) do begin
  if (UpperCase(AEvlErrors[i].eleLogName) = UpperCase(ELName)) then begin
   result := true;
   break;
  end;
 end;

end;
{$ENDREGION}

{ TUpdateList }

{$REGION UPDATES}
// *******************************************************************
//   Constructor
// *******************************************************************
constructor TUpdateList.Create(const IniFileName: String);
begin
 FFileName := IniFileName;
 Inherited Create(IniFileName);
end;
// *******************************************************************
//   Destructor
// *******************************************************************
destructor TUpdateList.Destroy;
begin
  inherited;
end;
// *******************************************************************
//   SetCurrentSection
// *******************************************************************
procedure TUpdateList.SetCurrentSection(const SectionTitle: String);
begin
 FCurrentSection := SectionTitle;
end;
// *******************************************************************
//   DeleteUpdate
// *******************************************************************
function TUpdateList.DeleteUpdate(const UpdateName: String): String;
begin

end;
// *******************************************************************
//   ModifyUpdate
// *******************************************************************
function TUpdateList.ModifyUpdate(const UpdateRec : TUpdateRecord): String;
begin
 WriteString(FCurrentSection, upd_par_Descr, UpdateRec.updDescr);
 WriteInteger(FCurrentSection, upd_par_OSFlags, UpdateRec.updOSFlags);
 WriteBool(FCurrentSection, upd_par_Checked, UpdateRec.updChecked);
 WriteString(FCurrentSection, upd_par_RegPath, UpdateRec.updRegPathx86);
 WriteString(FCurrentSection, upd_par_RegPath64, UpdateRec.updRegPathAMD64);
end;
// *******************************************************************
//   GetUpdateRecordForSection
// *******************************************************************
function TUpdateList.GetUpdateRecordForSection(var UR: TUpdateRecord): boolean;
begin
  if SectionExists(FCurrentSection) then begin
   UR.updDescr   := ReadString(FCurrentSection, upd_par_Descr, '');
   UR.updOSFlags := ReadInteger(FCurrentSection, upd_par_OSFlags, 0);
   UR.updChecked := ReadBool(FCurrentSection, upd_par_Checked, false);
   UR.updRegPathx86 := ReadString(FCurrentSection, upd_par_RegPath, '');
   UR.updRegPathAMD64 := ReadString(FCurrentSection, upd_par_RegPath64, '');
   result := true;
  end else
   result := false;
end;
// *******************************************************************
//   SelectSection
// *******************************************************************
procedure TUpdateList.SelectSection(isSelected: boolean);
begin
 WriteBool(FCurrentSection, upd_par_Checked, isSelected);
end;
// *******************************************************************
//   GetUpdatesForOS
// *******************************************************************
function TUpdateList.GetUpdatesForOS(OSCode: Integer; var sl: TStringList): Integer;
begin

end;
// *******************************************************************
//   GetOSListByOSCode
// *******************************************************************
function TUpdateList.GetOSListByOSCode(OSFlag : DWORD): String;
var
 TotalOsCount : Integer;
begin
 result := LC_EMPTY_STRING;
 TotalOsCount := 0;
   if ((OSFlag and OS_WIN_XP) = OS_WIN_XP) then begin
     Inc(TotalOsCount);
     result := 'XP';
   end;
   if ((OSFlag and OS_WIN_2003_SERVER) = OS_WIN_2003_SERVER) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2003';
   end;
   if ((OSFlag and OS_WIN_VISTA) = OS_WIN_VISTA) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'Vista';
   end;
   if ((OSFlag and OS_WIN_2008_SERVER) = OS_WIN_2008_SERVER) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2008';
   end;
   if ((OSFlag and OS_WIN_7) = OS_WIN_7) then begin
     Inc(TotalOsCount);
     result := result + ',' + '7';
   end;
   if ((OSFlag and OS_WIN_2008_SERVER_R2) = OS_WIN_2008_SERVER_R2) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2008R2';
   end;
   if ((OSFlag and OS_WIN_8) = OS_WIN_8) then begin
     Inc(TotalOsCount);
     result := result + ',' + '8';
   end;
   if ((OSFlag and OS_WIN_2012_SERVER) = OS_WIN_2012_SERVER) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2012';
   end;
   if ((OSFlag and OS_WIN_81) = OS_WIN_81) then begin
     Inc(TotalOsCount);
     result := result + ',' + '8.1';
   end;
   if ((OSFlag and OS_WIN_2012_SERVER_R2) = OS_WIN_2012_SERVER_R2) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2012R2';
   end;
   if ((OSFlag and OS_WIN_10_1507) = OS_WIN_10_1507) then begin
     Inc(TotalOsCount);
     result := result + ',' + '10 1507';
   end;
   if ((OSFlag and OS_WIN_10_1511) = OS_WIN_10_1511) then begin
     Inc(TotalOsCount);
     result := result + ',' + '10 1511';
   end;
   if ((OSFlag and OS_WIN_10_1607) = OS_WIN_10_1607) then begin
     Inc(TotalOsCount);
     result := result + ',' + '10 1607';
   end;
   if ((OSFlag and OS_WIN_10_1703) = OS_WIN_10_1703) then begin
     Inc(TotalOsCount);
     result := result + ',' + '10 1703';
   end;
   if ((OSFlag and OS_WIN_10_1803) = OS_WIN_10_1803) then begin
     Inc(TotalOsCount);
     result := result + ',' + '10 1803';
   end;
   if ((OSFlag and OS_WIN_2016_SERVER) = OS_WIN_2016_SERVER) then begin
     Inc(TotalOsCount);
     result := result + ',' + 'WS2016';
   end;

   if (TotalOsCount = OS_TOTAL_COUNT) then
    result := 'All';

   if (Length(result) > 0) then
    if result[1] =',' then
     delete(result, 1, 1);
 end;

{$ENDREGION}

Initialization
 glb_OS_Version := osGetOSVersion(glb_OS_VersionSTR, glb_OS_SPVersion);
 glb_RedirectLoaded := false;
 gfRedirectLoad();

 glb_ScanTerminateEvent := CreateEvent(nil, true, false, nil);
 glb_ICMPTerminateEvent := CreateEvent(nil, true, false, nil);
 glb_AppTerminateEvent  := CreateEvent(nil, true, false, nil);
 glb_EnvMonCommandEvent := CreateEvent(nil, true, false, nil);

 glb_KESServerNames := TStringList.Create();

 glb_FoldersToClear := TStringList.Create();
 glb_ServicesToDelete := TStringList.Create();

 glb_FoldersToClear.Add('c:\logfiles');
 glb_FoldersToClear.Add('c:\windows\system32\spool\printers');

 glb_ServicesToDelete.Add('DgiVecp');
 glb_ServicesToDelete.Add('SSPORT');


finalization

  {$IFDEF DEBUG_VER}
   FreeAndNil(dbgScan);
  {$ENDIF}

 CloseHandle(glb_ICMPTerminateEvent);
 CloseHandle(glb_ScanTerminateEvent);
 CloseHandle(glb_AppTerminateEvent);
 CloseHandle(glb_EnvMonCommandEvent);

 if Assigned(glb_CompNamesGeo) then
  FreeAndNil(glb_CompNamesGeo);
 if Assigned(glb_CompNamesOrg) then
  FreeAndNil(glb_CompNamesOrg);
 FreeAndNil(glb_KESServerNames);

 FreeAndNil(glb_FoldersToClear);
 FreeAndNil(glb_ServicesToDelete);

end.
