# Google OAuth2 Cmdlets

## Usage

This module provides 2 major use cases, getting an access token with OAuth2 client credentials provided from the GCP console or
from a GCP service account. There are multiple ways to use the cmdlets for OAuth2 client credentials. Retrieving tokens with OAuth2
client credentials require the use of a web browser the first time during the authorizaton code retrieval process. However, after this
first time, the access token and refresh token are cached for use throughout the rest of the script using these cmdlets, or optionally
persisted to disk so you can continue to use the set of tokens without needing to use a web browser again.

All sensitive data that is persisted in cache or on disk is encrypted using the Windows DPAPI. Because the access tokens, refresh tokens,
and service account private keys are very sensitive data, all cmdlets that either retrieve or refresh tokens have an optional -Persist
parameter. The profile data, indexed by the ClientId, is automatically saved to an in-memory cache that persists while the module
is loaded. However, it is never saved to disk unless the -Persist option is specified. If you have initially persisted profile data to disk,
but then subsequently call a command that updates an access token, like Update-GoogleOAuth2Token, but do not specifiy -Persist, the new
token is not written to disk, but is updated in the in memory cache. Calling Sync-GoogleOAuth2Profiles, or any cmdlet that calls that
cmdlet on your behalf would overwrite the new access token in the cache with the old value.

Assume the appropriate strings are assigned to $ClientId and $ClientSecret in the following examples

### OAuth2 Client Credential Examples

#### Example 1
A standard use case of retrieving tokens for the first time.

    $Code = Get-GoogleOAuth2Code -ClientId $ClientId -Scope "admin.directory.group.readonly"
	$Token = Convert-GoogleOAuth2Code -ClientId $ClientId -ClientSecret $ClientSecret -Code $Code -Persist
	$Groups = Get-GoogleAdminGroups -BearerToken $Token["access_token"]

#### Example 2
You could also use a set of tokens that you've previously retrieved and persist them to disk for use later.

	Set-GoogleOAuth2Profile -ClientId $ClientId -RefreshToken $RToken -ClientSecret $ClientSecret -Persist
	$Token = Get-GoogleOAuth2Token -ClientId $ClientId
	$Groups = Get-GoogleAdminGroups -BearerToken $Token["access_token"]

This will use the refresh token that is in the profile cache and retrieve a new access token during the Get-GoogleOAuth2Token cmdlet call.

#### Example 3
The Request-GoogleOAuth2Token cmdlet wraps some of the previous cmdlets

    $Token = Request-GoogleOAuth2Token -ClientId $ClientId -ClientSecret $ClientSecret -Scope "admin.directory.group.readonly" -Persist
	$Groups = Get-GoogleAdminGroups -BearerToken $Token["access_token"]

#### Example 4
If you want to refresh an access token manually

    $Token = Update-GoogleOAuth2Token -ClientId $ClientId -Persist

The updated access token is also persisted to disk with the other profile data.

#### Example 5
You may only want persist an access token for as long as its valid without other data

    Set-GoogleOAuth2Profile -ClientId $ClientId -AccessToken $AccessToken -Persist
	$Token = Get-GoogleOAuth2Token -ClientId $ClientId

The second command will throw an exception if the access token expires.

You could also call

	$Token = Request-GoogleOAuth2Token -ClientId $ClientId

### Service Account Examples

Service account credentials are handled slightly differently. You should persist the pertinent settings to a profile first, then
retrieve an access token.

#### Example 1

In this example, we save the service account details to disk, where the client secret is the PEM encoded RSA private key and 
the client id is the service account email. The Get-GoogleOAuth2Token call creates a JWT from the stored service account details,
exchanges that for an access token and returns it to the pipeline. This access token can be used just like an access token retrieved
from OAuth2 client credentials. The access token will be valid for as long as the JWT was valid for, which is 3600 seconds by default.
Each call to Get-GoogleOAuth2Token will refresh the access token if required, or just return the cached access token if it doesn't need
a refresh.

	Set-GoogleOAuth2Profile -ServiceAccountEmail $ClientId -ClientSecret $ClientSecret -Scope "admin.directory.group.readonly" -Persist -Subject "john.smith@google.com"
	$Token = Get-GoogleOAuth2Token -ClientId $ClientId -Persist
	$Groups = Get-GoogleAdminGroups -BearerToken $Token["access_token"]

## Release History

### 1.0.0.1
Fixed minor typo bug in Get-GoogleOAuth2Token.

### 1.0.0.0
Initial Release