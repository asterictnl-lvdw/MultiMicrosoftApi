<#
.SYNOPSIS
	Retrieves Azure tokens (e.g., for https://main.iam.ad.ext.azure.com) with the ability to bypass MFA by caching the RefreshToken. Works on both Linux, Unix and Windows. 
    Initial login requires interactivity; subsequent logins bypass MFA and do not require user interaction.
    This function invokes Microsoft APIs using REST methods (GET, POST, PUT, DELETE, OPTIONS) with MSAL authentication for token retrieval.

.DESCRIPTION
    `Invoke-MSALAPI` is a flexible function designed to call Microsoft APIs by handling OAuth2-based authentication using MSAL. The function sends API requests with various HTTP methods and uses a Bearer token for authorization, supporting both GET and POST requests with optional body data.

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

.PARAMETER Body
    The body of the request, if the method used requires one (POST, PUT). Typically, this is sent in JSON format.

.PARAMETER Method
    The HTTP method to use for the API request. Valid options include GET, POST, PUT, DELETE, and OPTIONS. Default is GET.

.EXAMPLE
    # Example GET request:
    $response = Invoke-MSALAPI -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                                           -ResourceId "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                                           -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                                           -Method "GET"

    # Example POST request with body:
    $body = @{
        'key' = 'value'
    } | ConvertTo-Json
    $response = Invoke-MSALAPI -Url "https://api.example.com/performAction" `
                                           -ResourceId "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                                           -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                                           -Body $body `
                                           -Method "POST"

.NOTES
    - Filename: Invoke-MSALAPI.ps1
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

function Invoke-MSALAPI
{

	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		[Parameter()]
		[String]$Scope = "user_impersonation",
		#The Name of the Resource
		[Parameter()]
		[String]$ResourceId,
		#ClientID
		[Parameter()]
		[String]$ClientId,
		#Body if a POST or PUT
		[Parameter()]
		[Object]$Body,
		#Specify the HTTP Method you wish to use. Defaults to GET
		[Parameter()]
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)

$Scopes = "$($ResourceId)/$($Scope)"
$MsalRequest = Get-MsalToken -ClientId $ClientId -Scopes $Scopes
$AccessToken = $MsalRequest.AccessToken

# Create the HTTP header with the necessary authorization and other metadata
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $AccessToken.ToString()
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
#Invoke the function above: We use Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" (Azure PowerShell) -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" (Internal Azure API) to execute the request
$MethodsRequired = Invoke-MSALAPI -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -Method 'GET'

#Output the response as test
$MethodsRequired | Format-List

