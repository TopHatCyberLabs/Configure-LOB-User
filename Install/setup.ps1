[CmdletBinding(DefaultParametersetName = "Create")]
param
(
    [Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
    [Alias("url")]
    [String]$PVWAURL,
    
    [Parameter(Mandatory = $true, HelpMessage = "Please enter your Primary Vault IP Address")]
    [String]$vaultIP,
    
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
     #add numbers
     for($a=48; $a -lt 58; $a++)
     {
        $sourcedata+=,[char][byte]$a
     }
     #add uppercase letters
     for($a=65; $a -lt 91; $a++)
     {
        $sourcedata+=,[char][byte]$a
     }
     #add lowercase letters
     for($a=97; $a -lt 123; $a++)
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
        return $vaultUserInitialPassword
    }
    catch {
        Add-LogMsg -type Error -MSG $_.Exception
    }
}

function Add-Account{
    param (
        [Parameter(Mandatory = $true)]
        [String]$acctUserName,
        [Parameter(Mandatory = $true)]
        [String]$acctAddress,
        [Parameter(Mandatory = $true)]
        [String]$platformId,
        [Parameter(Mandatory = $true)]
        [String]$safeName,
        [Parameter(Mandatory = $true)]
        [String]$secretType,
        [Parameter(Mandatory = $true)]
        [String]$secret,
        [Parameter(Mandatory = $false)]
        [String]$cyberArkAcctName
        )
    try {
        #Future Feature - Search for Account before adding. 
         $addAccountBody = @{ name=$cyberArkAcctName; userName=$acctUserName; address=$acctAddress; platformId=$platformId; safeName=$safeName; secretType=$secretType; secret=$secret} | ConvertTo-Json 
                if ($null -ne $(Invoke-Rest -Command Post -URI $API_Accounts -Header $g_LogonHeader -Body $addAccountBody)) {
                            
                    Add-LogMsg -type Info -MSG "Account $($acctUserName) successfully added to $($safeName) safe."
                } 
                else {
                    Add-LogMsg -type Error -MSG "Account $($acctUserName) could not be successfully added to $($safeName) safe."
                }
        }
        catch {
            Add-LogMsg -type Error -MSG $_.Exception
        }
}


function Add-SafePermissions{
    param( 
        [Parameter(Mandatory = $true)]
        [String]$safeName,
        [Parameter(Mandatory = $true)]
        [String]$userName
        )
          #List Safe members, parse to see if user above exists If it doesn't, Add, if it does, Update permissions
try {
    $listSafeMemberUri = $API_Safes + "/" + $safeName

    #Get JSON Response of ConjurSync Safe Members
    $safeMemberResult = Get-VaultObject $listSafeMemberUri
    $safeMembershipExists = $false

    #loop through JSON response to see if the vault user from above is already a member
    foreach ($safeMember in $safeMemberResult.members)    
    {
        if ($safeMember.UserName -eq $userName)
        {$safeMembershipExists = $true}
    }

    if($safeMembershipExists -eq $false)
    {
        #Add the safe member
        $newSafeMemberBody = @{member =
            @{MemberName = $userName
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
              Value = $false},
              @{Key = "UpdateAccountContent"
              Value = $false},
              @{Key = "UpdateAccountProperties"
              Value = $false},
              @{Key = "InitiateCPMAccountManagementOperations"
              Value = $false},
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
              Value = 0},
              @{Key = "AccessWithoutConfirmation"
              Value = $true},
              @{Key = "CreateFolders"
              Value = $false},
              @{Key = "DeleteFolders"
              Value = $false},
              @{Key = "MoveAccountsAndFolders"
              Value = $false}
              )
            }
            } | ConvertTo-Json -Depth 3
            
            $addSafeMemberUri = $API_Safes + "/" + $safeName +"/Members"
            if ($null -ne $(Invoke-Rest -Command Post -URI $addSafeMemberUri -Header $g_LogonHeader -Body $newSafeMemberBody)) {
                    
                Add-LogMsg -type Info -MSG "User $($userName) permissions successfully created for $($safeName) Safe."
            } 
            else {
                Add-LogMsg -type Error -MSG "User $($userName) could not be added to $($safeName) Safe."
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
              Value = $false},
              @{Key = "UpdateAccountContent"
              Value = $false},
              @{Key = "UpdateAccountProperties"
              Value = $false},
              @{Key = "InitiateCPMAccountManagementOperations"
              Value = $false},
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
              Value = 0},
              @{Key = "AccessWithoutConfirmation"
              Value = $true},
              @{Key = "CreateFolders"
              Value = $false},
              @{Key = "DeleteFolders"
              Value = $false},
              @{Key = "MoveAccountsAndFolders"
              Value = $false}
              )
            }
            } | ConvertTo-Json -Depth 3
            
            $updateSafeMemberUri = $API_Safes + "/" + $safeName + "/Members/" + $userName
            if ($null -ne $(Invoke-Rest -Command PUT -URI $updateSafeMemberUri -Header $g_LogonHeader -Body $updateSafeMemberBody)) {
                    
                Add-LogMsg -type Info -MSG "User $($userName) permissions successfully updated for $($safeName) Safe."
            } 
            else {
                Add-LogMsg -type Error -MSG "User $($userName) could not be updated for $($safeName) Safe."
            }
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
    if ($csvContent.Count -eq 1){
    $lineData = $csvContent.Split(",")
    }
    else{
    $lineData = $csvContent[$i].Split(",")
    }
    #This is where we add the EPV User
    $lobUserName = $lineData[0]
    $vaultUserPassword = Add-VaultUser($lobUserName)
   
    Add-Account -cyberArkAcctName $lobUserName -acctUserName $lobUserName -acctAddress $vaultIP -platformId "CyberArk" -safeName "ConjurSync" -secretType "password" -secret $vaultUserPassword

    
    for($j=1; $j -lt $lineData.Count; $j++){
    #assign permissions to each safe the LOB User will sync
    Add-SafePermissions -safeName $lineData[$j] -userName $lobUserName
    }
}

#region [Logoff]
# Logoff the session
# ------------------
Invoke-Rest -Uri $API_Logoff -Header $g_LogonHeader -Command "Post"
# Footer

#endregion