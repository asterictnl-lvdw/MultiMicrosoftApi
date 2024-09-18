# PowerShell API Invocation Functions

## Overview

This repository provides two PowerShell functions, `Invoke-MultiAzApi` and `Invoke-MSALAPI`, designed for interacting with Microsoft APIs. Both functions offer a convenient way to handle authentication (either via rest-request or via MSAL) and send requests to Microsoft or Azure API endpoints with support for multiple HTTP methods (GET, POST, PUT, DELETE, and OPTIONS).

## Functions Overview

### 1. Invoke-MultiAzApi
This function enables Microsoft API calls by retrieving OAuth2 tokens through interactive or non-interactive methods, supporting refresh tokens from cache or supplied by the user. Resulting into gaining information from Microsoft API's to audit specific settings within various products.

### 2. Invoke-MSALAPI
This function uses the Microsoft Authentication Library (MSAL) to acquire OAuth2 tokens for interacting with Microsoft resources, such as Graph API or custom resources, with specified scopes.

## Features

- **Token Management**: Both functions handle token acquisition, refresh, and caching.
- **Supports Multiple HTTP Methods**: Execute API requests with GET, POST, PUT, DELETE, and OPTIONS.
- **Error Handling**: Proper error handling and logging for failed authentication or API requests.
- **Custom Headers**: Automatically constructs the necessary HTTP headers for API requests, including unique request and correlation IDs.

## Prerequisites

- PowerShell 5.1 or later for Windows or PowerShell 7 for Linux and Unix systems
- `MSAL.PS` module installed for `Invoke-MSALApi`.
- The respective `Resource-Id` from registered applications with appropriate permissions for the target resource.
- The `url` of the API-endpoint you want to get information from.
- Valid `ClientId` for the applications.

## Parameters

### `Invoke-MultiAzApi` Parameters

| Parameter              | Description                                                                                   | Required | Default       |
|------------------------|-----------------------------------------------------------------------------------------------|----------|---------------|
| `Url`                  | The full URL to call the Azure API.                                                           | Yes      | None          |
| `Resource`             | The unique identifier of the resource (e.g., Azure AD or specific Azure resources).            | Yes      | None          |
| `ClientId`             | The Client ID of the Azure AD application.                                                    | Yes      | None          |
| `Body`                 | The body content for POST or PUT requests (optional).                                         | No       | None          |
| `Method`               | HTTP method for the API request (GET, POST, PUT, DELETE, OPTIONS).                            | No       | `GET`         |
| `refreshTokenCachePath`| Path to cache the refresh token.                                                              | No       | Current Path  |
| `refreshToken`         | A refresh token provided by the user.                                                         | No       | None          |

### `Invoke-MSALAPI` Parameters

| Parameter              | Description                                                                                   | Required | Default             |
|------------------------|-----------------------------------------------------------------------------------------------|----------|---------------------|
| `Url`                  | The full URL to call the Microsoft API endpoint.                                               | Yes      | None                |
| `Scope`                | The specific scope required for the API call (e.g., `user.read` or `user_impersonation`).      | No       | `user_impersonation`|
| `ResourceId`           | The unique identifier of the resource (e.g., https://graph.microsoft.com).                    | Yes      | None                |
| `ClientId`             | The Client ID of the Azure AD application.                                                    | Yes      | None                |
| `Body`                 | The body content for POST or PUT requests (optional).                                         | No       | None                |
| `Method`               | HTTP method for the API request (GET, POST, PUT, DELETE, OPTIONS).                            | No       | `GET`               |

## Usage

### Invoke-MultiAzApi

This function can handle authentication using refresh tokens, either supplied manually or retrieved from a cache. It supports making requests to Microsoft APIs using the retrieved access token.

#### Example: Basic GET Request

```powershell
$Response = Invoke-MultiAzApi -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                              -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                              -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                              -Method 'GET'

Write-Host $Response
```

#### Example: POST Request with Body

```powershell
$Body = @{
    'restrictNonAdminUsers' = $false
} | ConvertTo-Json

$Response = Invoke-MultiAzApi -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                              -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                              -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                              -Method 'POST' `
                              -Body $Body

Write-Host $Response
```

### Invoke-MSALAPI

This function uses MSAL to obtain access tokens for calling Microsoft APIs such as Microsoft Graph or other resources with defined scopes.

#### Example: Basic GET Request

```powershell
$Response = Invoke-MSALAPI -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                            -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                            -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                            -Method 'GET'

$Response | Format-List
```

#### Example: POST Request with Body

```powershell
$Body = @{
    'key' = 'value'
} | ConvertTo-Json

$Response = Invoke-MSALAPI -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" `
                            -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" `
                            -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" `
                            -Method 'POST' `
                            -Body $Body

$Response | Format-List
```

## Token Acquisition

Both functions handle the acquisition and caching of OAuth2 tokens.

- `Invoke-MultiAzApi` handles token acquisition through interactive logins, refresh tokens, and token caching.
- `Invoke-MSALAPI` uses the MSAL library to acquire tokens for the specified resource and scope.

### Example Token Acquisition (MSAL)

```powershell
$Scopes = "$($ResourceId)/$($Scope)"
$MsalRequest = Get-MsalToken -ClientId $ClientId -Scopes $Scopes
$AccessToken = $MsalRequest.AccessToken
```

## Error Handling

- **Invalid Token**: If the token request fails or is invalid, the function will not proceed with the API call.
- **Unsupported HTTP Methods**: Only the methods defined (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`) are supported.
- **Authentication Failures**: If the provided `ClientId` or `ResourceId` lacks necessary permissions, an error will be raised.

## Contributions

Contributions are welcome! Feel free to submit issues or pull requests for improvements, bug fixes, or additional functionality.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

_This project is not officially affiliated with Microsoft._