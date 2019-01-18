[CmdletBinding(DefaultParametersetName = "Create")]
param
(
    [Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("url")]
    [String]$PVWAURL,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify
)


# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Configure_LOB_User.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent



# Global URLS
# -----------
$URL_PVWA_Base_API = $PVWAURL + "/PasswordVault/api"
$URL_PIM_Base_API = $PVWAURL + "/PasswordVault/WebServices/PIMServices.svc"

# API Methods
# -----------
$API_Logon = $URL_PVWA_Base_API + "/auth/cyberark/logon"
$API_Logoff = $URL_PVWA_Base_API + "/auth/logoff"
$API_VaultUsers = $URL_PIM_Base_API + "/Users"
$API_Platforms = $URL_PVWA_Base_API + "/Platforms"
$API_Platforms_Import = $API_Platforms + "/Import"
$API_Safes = $URL_PIM_Base_API + "/Safes"
$API_Accounts = $URL_PVWA_Base_API + "/accounts"

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""


#region [Functions]
function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if (Get-Command $command) {RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference = $oldPreference}
}

function Add-LogMsg {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [String]$type = "Info"
    )

    If ($Header) {
        "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "======================================="
    }
    ElseIf ($SubHeader) { 
        "------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "------------------------------------"
    }

    $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
    $writeToFile = $true
    # Replace empty message with 'N/A'
    if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
    # Check the message type
    switch ($type) {
        "Info" {
            Write-Host $MSG.ToString()
            $msgToWrite += "[INFO]`t$Msg"
        }
        "Warning" {
            Write-Host $MSG.ToString() -ForegroundColor DarkYellow
            $msgToWrite += "[WARNING]`t$Msg"
        }
        "Error" {
            Write-Host $MSG.ToString() -ForegroundColor Red
            $msgToWrite += "[ERROR]`t$Msg"
        }
        "Debug" {
            if ($InDebug) {
                Write-Debug $MSG
                $msgToWrite += "[DEBUG]`t$Msg"
            }
            else { $writeToFile = $False }
        }
        "Verbose" {
            if ($InVerbose) {
                Write-Verbose $MSG
                $msgToWrite += "[VERBOSE]`t$Msg"
            }
            else { $writeToFile = $False }
        }
    }

    If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
    If ($Footer) { 
        "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
        Write-Host "======================================="
    }
}

function Get-LogonHeader {
    param($logonCred)
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username = $logonCred.username.Replace('\', ''); password = $logonCred.GetNetworkCredential().password } | ConvertTo-Json
    try {
        # Logon
        $logonToken = Invoke-RestMethod -Uri $API_Logon -Method "Post" -ContentType "application/json" -Body $logonBody
        Add-LogMsg -Type Debug -MSG "Successfully retrieved logon token."
    }
    catch {
        Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
        $logonToken = ""
    }
    If ([string]::IsNullOrEmpty($logonToken)) {
        Add-LogMsg -Type Error -MSG "Logon Token is Empty - Cannot login"
        exit
    }

    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)

    return $logonHeader
}

function Invoke-Rest {
    param ($Command, $URI, $Header, $Body, $ErrorAction = "Continue")

    $restResponse = ""
    try {
        Add-LogMsg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
        $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
    }
    catch {
        If ($null -ne $_.Exception.Response.StatusDescription) {
            Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
        }
        else {
            Add-LogMsg -Type Error -Msg "StatusCode: $_.Exception.Response.StatusCode.value__"
        }
        $restResponse = $null
    }
    Add-LogMsg -Type Verbose -MSG $restResponse
    return $restResponse
}


function Get-VaultObject {
    param ($commandUri)
    $_vaultObject = $null
    try {
        $_vaultObject = $(Invoke-Rest -Uri $commandUri -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
    }
    catch {
        Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
    }
    return $_vaultObject
}

function Get-RandomPassword() {

    Param(
    
    [int]$length=32
    
    )
    
     $sourcedata=$null
     for($a=48; $a -le 110; $a++)
     {
        $sourcedata+=,[char][byte]$a
     }
    for ($loop=1; $loop -le $length; $loop++)
    {
        $TempPassword+=($sourcedata | Get-Random)
    }
    return $TempPassword
}

function Add-VaultUser {
    param ($vaultUserName)
    #Test for existing vault user and create if it doesn't exist
    try {
        $userUri = $API_VaultUsers + '/' + $vaultUserName
        if ($null -eq $(Get-VaultObject $userUri )) {
            #User does not exist, so we need to create one
            $vaultUserInitialPassword = Get-RandomPassword 
            $createUserBody = @{ UserName = $vaultUserName; InitialPassword = $vaultUserInitialPassword; ChangePasswordOnTheNextLogon = $false; UserTypeName = "AppProvider"; Disabled = $false } | ConvertTo-Json
            if ($null -ne $(Invoke-Rest -Command Post -URI $API_VaultUsers -Header $g_LogonHeader -Body $createUserBody)) {
                        
                Add-LogMsg -type Info -MSG "EPV User Account $($vaultUserName) successfully created."
            } 
            else {
                Add-LogMsg -type Error -MSG "EPV User Account $($vaultUserName) could not be created."
            }
        }   
        else {
            #Write to log that the user already exists
            Add-LogMsg -type Info -MSG "Vault User $($vaultUserName) already exists, will not create vault user."
        }
    }
    catch {
        Add-LogMsg -type Error -MSG $_.Exception
    }
}

function Add-VaultUserAccount {
    param ()
    try {
        #Future Feature - Search for Account before adding. 
            $conjurHostCredentialsPath = Get-ChildItem -Name synchronizerConjurHost.xml -File -Path $ScriptLocation -Recurse
            $conjurHostCredentials = Import-Clixml -Path $conjurHostCredentialsPath
        
            $newAccountBody = @{ platformId="ConjurHost";safeName="ConjurSync";secretType="password";secret=$conjurHostCredentials.GetNetworkCredential().password;platformAccountProperties= @{ ConjurAccount=$conjurAccountName; HostName=$conjurHostCredentials.UserName; ApplianceURL="https://"+$conjurServerDNS }} | ConvertTo-Json
                if ($null -ne $(Invoke-Rest -Command Post -URI $API_Accounts -Header $g_LogonHeader -Body $newAccountBody)) {
                            
                    Add-LogMsg -type Info -MSG "Conjur Host $($conjurHostCredentials.Username) successfully added to CyberArk EPV."
                } 
                else {
                    Add-LogMsg -type Error -MSG "Conjur Host $($conjurHostCredentials.Username) could not be created in CyberArk EPV."
                }
        }
        catch {
            Add-LogMsg -type Error -MSG $_.Exception
        }
}
#endregion





# Check if to disable SSL verification
If($DisableSSLVerify)
{
try {
    #Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
    # Using Proxy Default credentials if the Sevrer needs Proxy credentials
     [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
  #  # Using TLS 1.2 as security protocol verification
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
 #   # Disable SSL Verification
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
}
catch {
    Add-LogMsg -Type Error -MSG "Could not change SSL validation"
    Add-LogMsg -Type Error -MSG $_.Exception
    exit
}
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Add-LogMsg -Type Error -MSG  "This script requires Powershell version 3 or above"
    exit
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
    If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
        $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
    }

    try {
        # Validate PVWA URL is OK
        Add-LogMsg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
        Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
    }
    catch [System.Net.WebException] {
        If (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
            Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
        }
    }
    catch {
        Add-LogMsg -Type Error -MSG "PVWA URL could not be validated"
        Add-LogMsg -Type Error -MSG $_.Exception
    }
}
else {
    Add-LogMsg -Type Error -MSG "PVWA URL can not be empty"
    exit
}



##Load csv file 
$csvContent = Get-Content .\lob_users.csv

#make sure lob_users.csv exists and has data
if ($null -eq $csvContent)
{
    Write-Host "Could not find lob_users.csv. Ensure the file exists in this directory. Nothing to do."
    exit
}

#region [Logon]
# Get Credentials to Login
# ------------------------
$title = "Vault Synchronizer Installation"
$msg = "Enter your User name and Password";
$creds = $Host.UI.PromptForCredential($title, $msg, "", "")
if ($null -ne $creds) {
    $g_LogonHeader = $(Get-LogonHeader $creds)
}
else {
    Add-LogMsg -Type Error -MSG "No Credentials were entered" -Footer
    exit
}
	
#endregion

#do this for each row
for ($i=0; $i -lt $csvContent.Count; $i++){
    #split data by comma
    $lineData = $csvContent[$i].Split(",")
    
    #This is where we add the EPV User
    Add-VaultUser($lineData[0])
    
    Add-VaultUserAccount

    
    for($j=1; $j -lt $lineData.Count){
    

#region [todo]
    
        #List Safe members, parse to see if user above exists If it doesn't, Add, if it does, Update permissions
try {
    $listSafeMemberUri = $API_Safes + "/" + $lineData[$j]

    #Get JSON Response of ConjurSync Safe Members
    $safeMemberResult = Get-VaultObject $listSafeMemberUri
    $safeMembershipExists = $false

    #loop through JSON response to see if the vault user from above is already a member
    foreach ($safeMember in $safeMemberResult.members)    
    {
        if ($safeMember.UserName -eq $lineData[$j])
        {$safeMembershipExists = $true}
    }

    if($safeMembershipExists -eq $false)
    {
        #Add the safe member
        $newSafeMemberBody = @{member =
            @{MemberName = $lineData[$j]
              SearchIn = "Vault"
              MembershipExpirationDate = ""
              Permissions = @(
                               @{Key = "UseAccounts"
              Value = $true},
              @{Key = "RetrieveAccounts"
              Value = $true},
              @{Key = "ListAccounts"
              Value = $true},
              @{Key = "AddAccounts"
              Value = $true},
              @{Key = "UpdateAccountContent"
              Value = $true},
              @{Key = "UpdateAccountProperties"
              Value = $true},
              @{Key = "InitiateCPMAccountManagementOperations"
              Value = $true},
              @{Key = "SpecifyNextAccountContent"
              Value = $false},
              @{Key = "RenameAccounts"
              Value = $false},
              @{Key = "DeleteAccounts"
              Value = $false},
              @{Key = "UnlockAccounts"
              Value = $false},
              @{Key = "ManageSafe"
              Value = $false},
              @{Key = "ManageSafeMembers"
              Value = $false},
              @{Key = "BackupSafe"
              Value = $false},
              @{Key = "ViewAuditLog"
              Value = $false},
              @{Key = "ViewSafeMembers"
              Value = $false},
              @{Key = "RequestsAuthorizationLevel"
              Value = 1},
              @{Key = "AccessWithoutConfirmation"
              Value = $true},
              @{Key = "CreateFolders"
              Value = $true},
              @{Key = "DeleteFolders"
              Value = $true},
              @{Key = "MoveAccountsAndFolders"
              Value = $false}
              )
            }
            } | ConvertTo-Json -Depth 3
            
            $addSafeMemberUri = $API_Safes + "/ConjurSync/Members"
            if ($null -ne $(Invoke-Rest -Command Post -URI $addSafeMemberUri -Header $g_LogonHeader -Body $newSafeMemberBody)) {
                    
                Add-LogMsg -type Info -MSG "User $($vaultSyncUserName) permissions successfully created for ConjurSync Safe."
            } 
            else {
                Add-LogMsg -type Error -MSG "User $($vaultSyncUserName) could not be added to ConjurSync Safe."
            }
    }
    else
    {
        #update safe permissions to ensure Sync User has appropriate permissions
        $updateSafeMemberBody = @{member =
            @{
              MembershipExpirationDate = ""
              Permissions = @(
                               @{Key = "UseAccounts"
              Value = $true},
              @{Key = "RetrieveAccounts"
              Value = $true},
              @{Key = "ListAccounts"
              Value = $true},
              @{Key = "AddAccounts"
              Value = $true},
              @{Key = "UpdateAccountContent"
              Value = $true},
              @{Key = "UpdateAccountProperties"
              Value = $true},
              @{Key = "InitiateCPMAccountManagementOperations"
              Value = $true},
              @{Key = "SpecifyNextAccountContent"
              Value = $false},
              @{Key = "RenameAccounts"
              Value = $false},
              @{Key = "DeleteAccounts"
              Value = $false},
              @{Key = "UnlockAccounts"
              Value = $false},
              @{Key = "ManageSafe"
              Value = $false},
              @{Key = "ManageSafeMembers"
              Value = $false},
              @{Key = "BackupSafe"
              Value = $false},
              @{Key = "ViewAuditLog"
              Value = $false},
              @{Key = "ViewSafeMembers"
              Value = $false},
              @{Key = "RequestsAuthorizationLevel"
              Value = 1},
              @{Key = "AccessWithoutConfirmation"
              Value = $true},
              @{Key = "CreateFolders"
              Value = $true},
              @{Key = "DeleteFolders"
              Value = $true},
              @{Key = "MoveAccountsAndFolders"
              Value = $false}
              )
            }
            } | ConvertTo-Json -Depth 3
            
            $updateSafeMemberUri = $API_Safes + "/ConjurSync/Members/" + $vaultSyncUserName
            if ($null -ne $(Invoke-Rest -Command Post -URI $updateSafeMemberUri -Header $g_LogonHeader -Body $updateSafeMemberBody)) {
                    
                Add-LogMsg -type Info -MSG "User $($vaultSyncUserName) permissions successfully updated for ConjurSync Safe."
            } 
            else {
                Add-LogMsg -type Error -MSG "User $($vaultSyncUserName) could not be updated for ConjurSync Safe."
            }
    }
}
catch {
    Add-LogMsg -type Error -MSG $_.Exception
}
#endregion 

    }
}


#check for user, add if doesn't exist
#if does exist, exit