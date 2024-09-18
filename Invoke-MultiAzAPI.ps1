<#
.SYNOPSIS
	Retrieves Azure tokens (e.g., for https://main.iam.ad.ext.azure.com) with the ability to bypass MFA by caching the RefreshToken. Works on both Linux, Unix and Windows. 
    Initial login requires interactivity; subsequent logins bypass MFA and do not require user interaction.
    This function invokes Microsoft APIs using REST methods (GET, POST, PUT, DELETE, OPTIONS) withhout dependencies for token retrieval.

.DESCRIPTION
    `Invoke-MultiAzApi` is a flexible function designed to call Microsoft APIs by handling OAuth2-based authentication using MSAL. The function sends API requests with various HTTP methods and uses a Bearer token for authorization, supporting both GET and POST requests with optional body data.

.FUNCTIONALITY
    This script is provided as-is, without warranty. It is intended for scenarios where an Azure token is needed to automate tasks that cannot be accomplished with service principals. 
    If the refresh token expires (default is 90 days of inactivity), you will need to rerun the script interactively.

.PARAMETER Url
    The full API endpoint URL to call (e.g., https://api.resource.com/v1/action).

.PARAMETER Scope
    The scope of the API request, defaulting to "user_impersonation". This specifies the level of access requested for the API.

.PARAMETER ResourceId
    The resource ID, which can be provided as an FQDN (e.g., "https://graph.microsoft.com") or a GUID. A list of valid GUIDs can be found here: https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in, or by using the Get-MgServicePrincipal cmdlet.

.PARAMETER ClientId
    The client ID in GUID format. A list of valid GUIDs can be found here: https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in, or by using the Get-MgServicePrincipal cmdlet.
    #ClientId you need to #use 1b730954-1685-4b74-9bfd-dac224a7b894 for audit/sign in logs or other things that only work through the AzureAD module, use d1ddf0e4-d672-4dae-b554-9d5bdfd93547 for Intune

.PARAMETER Username
    The username that is needed in order to retrieve the tenant-id.

.PARAMETER Body
    The body of the request, if the method used requires one (POST, PUT). Typically, this is sent in JSON format.

.PARAMETER Method
    The HTTP method to use for the API request. Valid options include GET, POST, PUT, DELETE, and OPTIONS. Default is GET.

.EXAMPLE
    # Example GET request:
    $response = Invoke-MultiAzApi -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                                           -ResourceId "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                                           -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                                           -Method "GET"

    # Example POST request with body:
    $body = @{
        'key' = 'value'
    } | ConvertTo-Json
    $response = Invoke-MultiAzApi -Url "https://api.example.com/performAction" `
                                           -ResourceId "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                                           -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                                           -Body $body `
                                           -Method "POST"

.NOTES
    - Filename: Invoke-MultiAzApi.ps1
    - Author: Leonardo van de Weteringh
    - Blog: localhost:1337
    - Created: 18/09/2024
    - Version: 1.0
    - This function requires the MSAL.PS module to retrieve tokens using `Get-MsalToken`.
    - Ensure you have the necessary permissions for the API being called.
    - The ResourceId must match the Azure service you're targeting.
    - Use the correct ClientId and Scopes to ensure a valid token is retrieved.
    - Error handling is performed using `-ErrorAction Stop` in Invoke-RestMethod.

#>

function Invoke-MultiAzApi
{

	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
        [Parameter()]
        [String]$Username,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		#ClientID
		[Parameter()]
		[String]$ClientId,
		#Body if a POST or PUT
		[Parameter()]
		[Object]$Body,
		[Parameter()]
		$refreshTokenCachePath=(Join-Path $pwd -ChildPath "azRfTknCache.cf"),
		[Parameter()]
		$refreshToken,
		#Specify the HTTP Method you wish to use. Defaults to GET
		[Parameter()]
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
# Retrieve the current time zone
$strCurrentTimeZone = (Get-TimeZone).Id
$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
[datetime]$origin = '1970-01-01 00:00:00'

#TenantID
$tenantId = (Invoke-RestMethod "https://login.windows.net/$($Username.Split("@")[1])/.well-known/openid-configuration" -Method GET).userinfo_endpoint.Split("/")[3]

# If a refresh token is provided, attempt to use it to get a new access token
if($refreshToken){
    try{
        Write-Host "checking provided refresh token and updating it"
        $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$refreshToken" -ErrorAction Stop)
        $refreshToken = $response.refresh_token
        $AccessToken = $response.access_token
        write-Host "refresh and access token updated"
    }catch{
        Write-Output "Failed to use cached refresh token, need interactive login or token from cache"   
        $refreshToken = $False 
    }
}

# If no refresh token is provided but a cache file exists, try to use the cached token
if([System.IO.File]::Exists($refreshTokenCachePath) -and !$refreshToken){
    try{
        Write-Host "getting refresh token from cache"
        $refreshToken = Get-Content $refreshTokenCachePath -ErrorAction Stop | ConvertTo-SecureString -ErrorAction Stop

        $refreshToken = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($refreshToken)
        $refreshToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($refreshToken)
        $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$refreshToken" -ErrorAction Stop)
        $refreshToken = $response.refresh_token
        $AccessToken = $response.access_token
        Write-Host "tokens updated using cached token"
    }catch{
        Write-Output "Failed to use cached refresh token, need interactive login"
        $refreshToken = $False
    }
}

# If no refresh token is available, perform an interactive login
if(!$refreshToken){
    Write-Host "No cache file exists and no refresh token supplied, we have to perform interactive logon"

    # Ensure the script is running interactively if required
    if ([Environment]::UserInteractive) {
        foreach ($arg in [Environment]::GetCommandLineArgs()) {
            if ($arg -like '-NonI*') {
                Throw "Interactive login required, but script is not running interactively. Run once interactively or supply a refresh token with -refreshToken"
            }
        }
    }

    try{
        Write-Host "Attempting device sign in method..."
        $response = Invoke-RestMethod -Method POST -UseBasicParsing -Uri "https://login.microsoftonline.com/$tenantId/oauth2/devicecode" -ContentType "application/x-www-form-urlencoded" -Body "resource=https%3A%2F%2Fgraph.microsoft.com&client_id=$clientId"
        Write-Host "$($response.message)"
        $waited = 0
        while($true){
            try{
                $authResponse = Invoke-RestMethod -uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Method POST -Body "grant_type=device_code&resource=https%3A%2F%2Fgraph.microsoft.com&code=$($response.device_code)&client_id=$clientId" -ErrorAction Stop
                $refreshToken = $authResponse.refresh_token
                break
            }catch{
                if($waited -gt 300){
                    Write-Host "No valid login detected within 5 minutes"
                    Throw
                }
                #try again
                Start-Sleep -s 5
                $waited += 5
            }
        }
    }catch{
        Throw "Interactive login failed, cannot continue"
    }
}

# Cache the new refresh token if available
if($refreshToken){
    Write-Host "caching refresh token..."
    Set-Content -Path $refreshTokenCachePath -Value ($refreshToken | ConvertTo-SecureString -AsPlainText -Force -ErrorAction Stop | ConvertFrom-SecureString -ErrorAction Stop) -Force -ErrorAction Continue | Out-Null
    Write-Host "refresh token cached..."
}else{
    Throw "No refresh token found in cache and no valid refresh token passed or received after login, cannot continue"
}

# Translate the refresh token into a resource-specific access token
try{
    Write-Host "update token for supplied resource"
    $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "resource=$([System.Web.HttpUtility]::UrlEncode($resource))&grant_type=refresh_token&refresh_token=$refreshToken&client_id=$clientId&scope=openid" -ErrorAction Stop)
    $resourceToken = $response.access_token
    Write-Host "token translated to $resource"
}catch{
    Throw "Failed to translate access token to $resource , cannot continue"
}

# Create the HTTP header with the necessary authorization and other metadata
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $resourceToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	
	# Specify the HTTP method for the request
	$method = 'GET'
	
	
	# Handle different HTTP methods (GET, POST, PUT) based on the chosen method
	if ($method -eq 'PUT')
	{
		# Prepare and send a PUT request
		$contentpart1 = '{"restrictNonAdminUsers":false}' # Example payload for PUT request
		$Body = $contentpart1
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		# Prepare and send a POST request
		Write-Host "Executing POST Request..."
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		# Prepare and send a GET request
		Write-Host "Executing GET Request..."
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
    return $Response
}
#Invoke the function above: We use Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" (Azure PowerShell) -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" (Internal Azure API)
$Username = Read-Host "Input your emailaddress:"
$MethodsRequired = Invoke-MultiAzApi -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -Method 'GET' -Username $Username

#Output the response
Write-Host $MethodsRequired

