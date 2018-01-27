[System.Collections.Hashtable]$script:OAuthTokens = @{}
$script:ProfileLocation = "$env:USERPROFILE\.google\credentials"
[System.String[]]$script:NoUrlScopes = @("https://mail.google.com/", "profile", "email", "openid", "servicecontrol", "cloud-platform-service-control", "service.management")
[System.String[]]$script:EncryptedProperties = @("access_token", "refresh_token", "client_secret", "jwt")
[System.String[]]$script:Scopes = @(
	"xapi.zoo",
    "adexchange.buyer",
    "adexchange.buyer",
    "adexchange.seller",
    "admin.datatransfer",
    "admin.datatransfer.readonly",
    "admin.directory.customer",
    "admin.directory.customer.readonly",
    "admin.directory.device.chromeos",
    "admin.directory.device.chromeos.readonly",
    "admin.directory.device.mobile",
    "admin.directory.device.mobile.action",
    "admin.directory.device.mobile.readonly",
    "admin.directory.domain",
    "admin.directory.domain.readonly",
	"admin.directory.group",
    "admin.directory.group.member",
    "admin.directory.group.member.readonly",
    "admin.directory.group.readonly",
    "admin.directory.notifications",
    "admin.directory.orgunit",
    "admin.directory.orgunit.readonly",
    "admin.directory.resource.calendar",
    "admin.directory.resource.calendar.readonly",
    "admin.directory.rolemanagement",
    "admin.directory.rolemanagement.readonly",
    "admin.directory.user",
    "admin.directory.user.alias",
    "admin.directory.user.alias.readonly",
    "admin.directory.user.readonly",
    "admin.directory.user.security",
    "admin.directory.userschema",
    "admin.directory.userschema.readonly",
    "admin.reports.audit.readonly",
    "admin.reports.usage.readonly",
    "adsense",
    "adsense.readonly",
    "adsensehost",
    "analytics",
    "analytics.edit",
    "analytics.manage.users",
    "analytics.manage.users.readonly",
    "analytics.provision",
    "analytics.readonly",
    "androidenterprise",
    "androidmanagement",
    "androidpublisher",
    "appengine.admin",
    "cloud-platform",
    "cloud-platform.read-only",
    "activity",
    "drive",
    "drive.metadata",
    "drive.metadata.readonly",
    "drive.readonly"
)

#region Base64Url

Function ConvertTo-Base64UrlEncoding {
	[CmdletBinding()]
	[OutputType([System.String])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "Input")]
		[AllowEmptyString()]
		[System.String]$InputObject,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Bytes")]
		[ValidateNotNull()]
		[System.Byte[]]$Bytes,

		[Parameter(ParameterSetName = "Input")]
		[ValidateNotNull()]
		[System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

		[Parameter()]
		[ValidateNotNull()]
		[System.Char]$Padding = '='
	)

	Begin {

	}

	Process {
		if ($PSCmdlet.ParameterSetName -eq "Input")
		{
			$Bytes = $Encoding.GetBytes($InputObject)
		}

		$Temp = [System.Convert]::ToBase64String($Bytes)
		$Temp = $Temp.TrimEnd($Padding).Replace('+', '-').Replace('/', '_')

		Write-Output -InputObject $Temp
	}

	End {

	}

}

Function ConvertFrom-Base64UrlEncoding {
	[CmdletBinding()]
	[OutputType([System.String])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[AllowEmptyString()]
		[System.String]$InputObject,

		[Parameter()]
		[ValidateNotNull()]
		[System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

		[Parameter()]
		[ValidateNotNull()]
		[System.Char]$Padding = '='
	)

	Begin {

	}

	Process {
		$InputObject = $InputObject.Replace('-', '+').Replace('_', '/')

		switch ($InputObject.Length % 4) {
			0 {
				break
			}
			2 {
				$InputObject += "$Padding$Padding"
				break
			}
			3 {
				$InputObject += "$Padding"
			}
			default {
				Write-Error -Exception (New-Object -TypeName System.ArgumentException("InputObject", "The input object is not a legal base64 string.")) -ErrorAction Stop
			}
		}

		$Temp = $Encoding.GetString([System.Convert]::FromBase64String($InputObject))

		Write-Output -InputObject $Temp
	}

	End {
	}
}

#endregion


#region Auth Code

Function Get-GoogleOAuth2Code {
    <#
		.SYNOPSIS
			Gets an authorization code for specified scopes to be granted Google OAuth2 credentials.

		.DESCRIPTION
			This cmdlet initiates the user approval for access to data and opens a browser window for the user to
			login and provide consent to the access. After approval, the browser will present an authorization code
			that should be pasted back into the prompt presented to the user. The code is sent out the pipeline, which 
			should be supplied to Get-GoogleOAuth2Token in order to get Google OAuth2 bearer tokens.

		.PARAMETER ClientId
			The supplied client id for OAuth.
			
		.PARAMETER ClientSecret
			The supplied client secret for OAuth.

		.PARAMETER Email
			The user's GSuite/Google user email to provide as a login hint to the login and consent page.

		.PARAMETER Scope
			The scope or scopes to be authorized in the OAuth tokens.

		.PARAMETER AccessType
			Indicates the module can refresh access tokens when the user is not present at the browser. This value 
			instructs the Google authorization server to return a refresh token and an access token the first time 
			that the cmdlet exchages an authorization code for tokens. You should always specify "offline", which
			is the default.

		.PARAMETER ResponseType
			How the Google Authorization server returns the code:

			Setting to "token" instructs the Google Authorization Server to return the access token as a name=value 
			pair in the hash (#) fragment of the URI to which the user is redirected after completing the authorization process.
			You must specify "online" as the AccessType with this setting and provide an actual redirect url.

			Setting to "code" instructs the Google Authorization Server to return the access code as an element in the web browser
			that can be copy and pasted into PowerShell.

			You should always specify "code" for this cmdlet, which is the default.

		.PARAMETER NoWebBrowser
			This parameter is not yet supported and will throw an error.

		.PARAMETER NoPrompt
			Indicates that the user receives no prompt in the web browser, which will likely result in a failed attempt or an access denied error. You
			shouldn't specify this parameter.

		.EXAMPLE
			$Code = Get-GoogleOAuth2Code -ClientId $Id -ClientSecret $Secret -Email john.smith@google.com -Scope "admin.directory.group.readonly"

			Gets an authorization code for the user to be able to exchange it for a long-term access token with the ability to have
			read-only access to groups in GSuite through the Google Directory API.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Email,

        [Parameter(ParameterSetName = "code")]
        [ValidateSet("online", "offline")]
        [System.String]$AccessType = "offline",

        [Parameter(ParameterSetName = "code")]
        [ValidateSet("code", "token")]
        [System.String]$ResponseType = "code",

        #[Parameter()]
        #[Switch]$NoWebBrowser,

        [Parameter(ParameterSetName = "code")]
        [Switch]$NoPrompt
    )

	DynamicParam {
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

		$ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute
		$ParameterAttribute.Mandatory = $true
		$AttributeCollection.Add($ParameterAttribute)


		$ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($script:Scopes)
		$AttributeCollection.Add($ValidateSetAttribute)

		$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Scope", ([System.String[]]), $AttributeCollection)
		$RuntimeParameterDictionary.Add("Scope", $RuntimeParameter)

		return $RuntimeParameterDictionary
	}

    Begin {
        # This redirect tells Google to display the authorization code in the web browser
        [System.String]$Redirect = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
    }

    Process {

        $ClientId = [System.Uri]::EscapeUriString($ClientId)

		$Scope = $PSBoundParameters["Scope"]

        [System.String[]]$FinalScopes = @()

        foreach ($Item in $Scope)
        {
            if ($Item -notin $script:NoUrlScopes)
            {
                $FinalScopes += "https://www.googleapis.com/auth/$Item"
            }
            elseif ($Item -eq "cloud-platform-service-control")
            {
                # cloud-platform is used both with a preceding url for some services and without for cloud service control APIs
                $FinalScopes += "cloud-platform"
            }
            else
            {
                $FinalScopes += $Item
            }
        }

		[System.String]$Scopes = [System.Uri]::EscapeUriString($FinalScopes -join ",")

		[System.String]$StateVariable="ps_state"

		[System.String]$OAuth = "https://accounts.google.com/o/oauth2/v2/auth?client_id=$ClientId&redirect_uri=$Redirect&scope=$Scopes&access_type=$AccessType&include_granted_scopes=true&response_type=$ResponseType&state=$StateVariable"

		if ($NoPrompt)
		{
			$OAuth += "&prompt=none"
		}

		if (-not [System.String]::IsNullOrEmpty($Email))
		{
			$OAuth += "&login_hint=$([System.Uri]::EscapeUriString($Email))"
		}
        
		try 
		{
			$Code = ""

			# Get the redirect url
			[Microsoft.PowerShell.Commands.WebResponseObject]$RedirectResponse = Invoke-WebRequest -Uri $OAuth -Method Get -MaximumRedirection 0 -ErrorAction Ignore -UserAgent PowerShell
        
			Write-Verbose -Message "Response Code: $($RedirectResponse.StatusCode)"

			# If the response is a redirect, that's what we expect
			if ($RedirectResponse.StatusCode.ToString().StartsWith("30"))
			{
				[System.Uri]$Redirect = $RedirectResponse.Headers.Location

				Write-Verbose -Message "Redirect location: $Redirect"

				if ($NoWebBrowser)
				{   
					<#  
						[System.Collections.Hashtable]$Query = @{}

						# Remove leading "?"
						$Redirect.Query.Substring(1) -split "&" | ForEach-Object {
							$Parts = $_ -split "="
							$Query.Add($Parts[0], $Parts[1])
						}
        
						# Get the first page, it could be an account selection page, a password entry page, or a the consent page       
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$SignInResponse = Invoke-WebRequest -Uri $Redirect -Method Get

						$SignInResponse.ParsedHtml.GetElementById("Email").value = $Query["Email"]
                    
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$NextResponse = Invoke-WebRequest -Uri $SignInResponse.Forms[0].Action -Body $SignInResponse.Forms[0] -Method Post
                    

						$StateWrapper = $NextResponse.ParsedHtml.GetElementById("state_wrapper").value

						$SignInUrl = "https://accounts.google.com/o/oauth2/approval?hd=$Org&as=$As&pageId=none&xsrfsign=$XSRF"
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$CodeResponse = Invoke-WebRequest -Uri $NextResponse.Forms[0].Action -Method Post
                
						# Title looks like:
						# Success state=<state_var>&amp;code=<oauth_code>&amp;scope=<scope_var>
						$Title = $CodeResponse.ParsedHtml.GetElementsByTagName("title") | Select-Object -First 1 -ExpandProperty text
						$Code = ($Title -ireplace "&amp", "") -split ";" | Where-Object {$_ -ilike "code=*" } | Select-Object -First 1 
						$Code = ($Code -split "=")[1]
					#>
					Write-Warning -Message "No browser option isn't supported yet."
				}
				else
				{           
					Write-Verbose -Message "Please open $Redirect in your browser"
            
					try 
					{
						# This will launch a web browser with the provided url
						& start $Redirect

						while ([System.String]::IsNullOrEmpty($Code))
						{
							$Code = Read-Host -Prompt "Enter authorization code from web browser"
						}
					}
					catch [Exception]
					{
						if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
						{
							Write-Error -Message "Could not open a web browser" -Exception $_.Exception -ErrorAction Stop
						}
						else
						{
							Write-Warning -Message "Could not open a web browser: $($_.Exception.Message)"
						}
					}
				}

				# This is where we normally return
				Write-Output -InputObject $Code
			}
			else
			{
				Write-Error -Message $RedirectResponse.RawContent
			}
		}
		catch [System.Net.WebException] 
		{
			[System.Net.WebException]$Ex = $_.Exception
			$Stream = $Ex.Response.GetResponseStream()
			[System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
			[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
			$Content = $Reader.ReadToEnd()
            
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Message $Content -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $Content
			}
		}
		catch [Exception] 
		{
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Exception $_.Exception -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $_.Exception.Message
			}
		}
    }

    End {
    }
}

Function Convert-GoogleOAuth2Code {
	<#
		.SYNOPSIS
			Exchanges an OAuth2 code for an access token.

		.DESCRIPTION
			This cmdlet exchanges an OAuth2 code for an access token and refresh token that can used
			to authenticate a user to Google APIs.

		.PARAMETER Code
			The one-time use authorization code received from Google.

		.PARAMETER ClientId
			The provided ClientId.
		
		.PARAMETER ClientSecret
			The provided ClientSecret.

		.PARAMETER GrantType
			The type of token being exchanged, in this case always authorization_code.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.PARAMETER Persist
			Indicates that the retrieved access tokens and client secret will be persisted on disk in an encrypted
			format using the Windows DPAPI as well as the local in-memory cache (also encrypted).

		.EXAMPLE
			$Code = Get-GoogleOAuth2Code -ClientId $Id -ClientSecret $Secret
			Convert-GoogleOAuth2Code -Code $Code -ClientId $Id -ClientSecret $Secret -Persist

			This example retrieves an authorization code and then exchanges it for long term access and refresh tokens. The token data and client
			secret are persisted to disk in an encrypted format.

		.INPUTS 
			None
		
		.OUTPUTS
			None

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2018
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Code,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter()]
        [ValidateSet("authorization_code")]
        [System.String]$GrantType = "authorization_code",

        [Parameter()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [Switch]$Persist
	)

	Begin {
		$Base = "https://www.googleapis.com/oauth2/v4/token"
		$CodeRedirect = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
	}

	Process {
		Write-Verbose -Message "Exchanging OAuth2 code for an access token."

		$Code = [System.Uri]::EscapeUriString($Code)
		$ClientId = [System.Uri]::EscapeUriString($ClientId)
		$ClientSecret = [System.Uri]::EscapeUriString($ClientSecret)
		$GrantType = "authorization_code"

		$Url = "$Base`?code=$Code&client_id=$ClientId&client_secret=$ClientSecret&redirect_uri=$CodeRedirect&grant_type=$GrantType"

		try 
		{
			[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $Url -Method Post -UserAgent PowerShell

			Write-Verbose -Message $Response.Content

			[PSCustomObject]$Data = ConvertFrom-Json -InputObject $Response.Content

			# Update the cache and persisted data
			Set-GoogleOAuth2Profile -ClientId $ClientId -ClientSecret $ClientSecret -AccessToken $Data.access_token -RefreshToken $Data.refresh_token -ProfileLocation $ProfileLocation -Persist:$Persist
			[System.Collections.Hashtable]$Token = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation
			Write-Output -InputObject $Token
		}
		catch [System.Net.WebException] 
		{
			[System.Net.WebException]$Ex = $_.Exception
			$Stream = $Ex.Response.GetResponseStream()
			[System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
			[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
			$Content = $Reader.ReadToEnd()
            
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Message $Content -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $Content
			}
		}
		catch [Exception] 
		{
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Exception $_.Exception -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $_.Exception.Message
			}
		}
	}

	End {
	}
}

Function Convert-GoogleOAuth2JWT {
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
		[ValidateScript({
			$_.Split(".").Length -eq 3
		})]
        [System.String]$JWT,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

		[Parameter()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [Switch]$Persist
	)

	Begin {
	}

	Process {
		$GrantType = [System.Uri]::EscapeUriString("urn:ietf:params:oauth:grant-type:jwt-bearer")
		$Assertion = $JWT

		$Body = "grant_type=$GrantType&assertion=$Assertion"

		$SAUrl = "https://www.googleapis.com/oauth2/v4/token"

		try {
			Write-Verbose -Message "POST Body: $Body"
			[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $SAUrl -Method Post -Body $Body -ErrorAction Ignore -UserAgent PowerShell

			[PSCustomObject]$Token = ConvertFrom-Json -InputObject ($Response.Content)

			[System.Collections.Hashtable]$Temp = @{}

			foreach ($Item in (Get-Member -InputObject $Token -MemberType Properties | Select-Object -ExpandProperty Name))
			{
				$Temp.Add($Item, $Token.$Item)
			}

			[System.String[]]$JWTParts = $JWT.Split(".")

			[PSCustomObject]$JWTClaimSet = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($JWTParts[1])))

			Set-GoogleOAuth2Profile -ServiceAccountEmail $ClientId -AccessToken $Temp["access_token"] -ProfileLocation $ProfileLocation -Persist:$Persist

			Write-Output -InputObject $Temp
		}
		catch [System.Net.WebException] 
		{
			[System.Net.WebException]$Ex = $_.Exception
			$Stream = $Ex.Response.GetResponseStream()
			[System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
			[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
			$Content = $Reader.ReadToEnd()
            
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Message $Content -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $Content
			}
		}
		catch [Exception] 
		{
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Exception $_.Exception -ErrorAction Stop
			}
			else
			{
				Write-Warning -Message $_.Exception.Message
			}
		}
	}

	End {
	}
}

#endregion


#region Tokens

Function Request-GoogleOAuth2Token {
	<#

	#>
	[CmdletBinding(DefaultParameterSetName = "Refresh")]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true)]
		[System.String]$ClientId,

		[Parameter(Mandatory = $true, ParameterSetName = "Code")]
		[System.String]$Code,

		[Parameter(Mandatory = $true, ParameterSetName = "Code")]
		[Parameter(Mandatory = $true, ParameterSetName = "RefreshFromToken")]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientSecret,

		[Parameter(Mandatory = $true, ParameterSetName = "RefreshFromToken")]
		[ValidateNotNullOrEmpty()]
		[System.String]$RefreshToken,

		[Parameter()]
		[Switch]$Persist,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
	}

	Process {
		switch ($PSCmdlet.ParameterSetName)
		{
			"Code" {
				$Token = Convert-GoogleOAuth2Code -Code $Code -ClientId $ClientId -ClientSecret $ClientSecret -ProfileLocation $ProfileLocation -Persist:$Persist
				Write-Output -InputObject $Token
				break
			}
			"RefreshFromToken" {
				$Token = Update-GoogleOAuth2Token -ClientId $ClientId -RefreshToken $RefreshToken -ClientSecret $ClientSecret -ProfileLocation $ProfileLocation -Persist:$Persist
				Write-Output -InputObject $Token
				break
			}
			"Refresh" {
				$Token = Update-GoogleOAuth2Token -ClientId $ClientId -ProfileLocation $ProfileLocation -Persist:$Persist
				Write-Output -InputObject $Token
				break
			}
			default {
				Write-Error -Message "Unknown parameter set $($PSCmdlet.ParameterSetName)." -ErrorAction Stop
			}
		}
	}

	End {
	}
}

Function Get-GoogleOAuth2Token {   
	<#
		.SYNOPSIS
			Retrieves a current access token from the in-memory cache or local disk.

		.DESCRIPTION
			This cmdlet retrieves the token set for the specified ClientId, either from the in-memory cache
			or the local disk if it is persisted. The access_token is analyzed to see if it is valid, and if not,
			it is automatically updated if a refresh token is present.

		.PARAMETER ClientId
			The key value the token set is stored as.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.PARAMETER Persist
			Specifies that if the access token needs to be refreshed during retrieval that the updated access token is persisted to disk.

		.EXAMPLE
			$Token = Get-GoogleOAuth2Token -ClientId $Id -Persist

			This example retrieves the stored tokens and client secret associated with the provided client Id and persists the updated
			access token if it needs to be refreshed.

		.INPUTS
			System.String

		.OUTPUTS
			System.Collections.Hashtable

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/18/2018
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [Switch]$Persist
    )

    Begin {
    }

    Process {
		Write-Verbose -Message "Getting OAuth2 token from cache."

		[System.Collections.Hashtable]$Token = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

		if ($Token -eq $null)
		{
			Write-Error -Exception (New-Object -TypeName System.Collections.Generic.KeyNotFoundException("No stored tokens for profile $ClientId.")) -ErrorAction Stop
		}

		if (-not $Token.ContainsKey("client_secret"))
		{
			Write-Error -Exception (New-Object -TypeName System.Collections.Generic.KeyNotFoundException("The stored token for profile $ClientId does not contain the required client_secret.")) -ErrorAction Stop
		}

		Write-Verbose -Message "Cache contains profile information for $ClientId."

		switch ($Token["type"])
		{
			"client" {
				# If the token contains an refresh token, we should check to see if we need to get
				# or renew the access token
				if ($Token.ContainsKey("refresh_token"))
				{
					[System.Collections.Hashtable]$TokenToReturn = @{}

					# If there's an access token and refresh token, let's make sure it's up to date
					if ($Token.ContainsKey("access_token"))
					{
						# Check the access token to see if it's expired, if it is, refresh, otherwise, return as is

						$Expired = Test-IsGoogleOAuth2TokenExpired -AccessToken $Token["access_token"]

						if ($Expired)
						{
							Write-Verbose -Message "The current access token is expired, getting a new one."
							# This will update the cache and persisted data store if necessary
							$TokenToReturn = Update-GoogleOAuth2Token -RefreshToken $Token["refresh_token"] -ClientId $ClientId -ClientSecret $Token["client_secret"] -Persist:$Persist
						}
						else
						{
							Write-Verbose -Message "The current access token is valid."
							# No need to do anything, use the token we found in the cache
							$TokenToReturn = $Token
						}
					}
					else
					{
						# The stored profile doesn't contain a current access_token, go ahead and request one with the
						# refresh token
						# Since there wasn't a persisted access_token, either on disk or in the cache, this will add that access_token to the
						# cache so we can continue to use it later
						$TokenToReturn = Update-GoogleOAuth2Token -RefreshToken $Token["refresh_token"] -ClientId $ClientId -ClientSecret $Token["client_secret"] -Persist:$Persist
					}

					Write-Output -InputObject $TokenToReturn
				}
				elseif ($Token.ContainsKey("access_token"))
				{
					# There's no refresh token, so just use this and hope it's not expired
					Write-Output -InputObject $Token
				}
				else
				{
					# This shouldn't happen since the cmdlet to modify the profile requires at least 1 token to be set, but
					# best to check it anyways, might have been edited manually
					Write-Verbose -Message "No stored tokens found for $ClientId, removing it from the cache and persisted data store."
					Remove-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

					Write-Error -Message "No stored tokens for profile $ClientId." -ErrorAction Stop
				}
				break
			}
			"sa" {
				if ($Token.ContainsKey("access_token"))
				{
					if ($Token.ContainsKey("jwt"))
					{
						[System.String[]]$JWTParts = $Token["jwt"].Split(".")
						
						if ($JWTParts.Length -eq 3)
						{
							[System.String]$Json = ConvertFrom-Base64UrlEncoding -InputObject $JWTParts[1]
							[PSCustomObject]$JWTClaims = ConvertFrom-Json -InputObject $Json
						
							[System.Int64]$Expires = $JWTClaims.exp

							[System.DateTime]$Expiration = (New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).AddSeconds($Expires)
							Write-Verbose -Message "The current JWT expires $($Expiration.ToString("yyyy-MM-ddTHH:mm:ssZ"))."

							[System.Boolean]$Expired = ([System.DateTime]::UtcNow) -gt $Expiration
			
							if ($Expired)
							{
								[System.String]$NewJWT = New-GoogleServiceAccountJWT -ClientSecret $Token["client_secret"] -Issuer $JWTClaims.iss -Scope $JWTClaims.scope -Subject $JWTClaims.sub

								[System.Collections.Hashtable]$Tok = Convert-GoogleOAuth2JWT -JWT $NewJWT -ClientId $ClientId -ClientSecret $Token["client_secret"] -ProfileLocation $ProfileLocation -Persist:$Persist
								Write-Output -InputObject $Tok
							}
							else
							{
								Write-Output -InputObject $Token
							}
						}
						else
						{
							Write-Error -Exception (New-Object -TypeName System.ArgumentException("jwt", "The stored JWT for $ClientId is not correctly formatted.")) -ErrorAction Stop
						}
					}
					else
					{
						Write-Output -InputObject $Token
					}
				}
				else
				{
					if ($Token.ContainsKey("jwt"))
					{
						[System.String[]]$JWTParts = $Token["jwt"].Split(".")

						if ($JWTParts.Length -eq 3)
						{
							[System.String]$Json = ConvertFrom-Base64UrlEncoding -InputObject $JWTParts[1]
							[PSCustomObject]$JWTClaims = ConvertFrom-Json -InputObject $Json
							[System.String]$NewJWT = New-GoogleServiceAccountJWT -ClientSecret $Token["client_secret"] -Issuer $JWTClaims.iss -Scope $JWTClaims.scope -Subject $JWTClaims.sub

							[System.Collections.Hashtable]$Tok = Convert-GoogleOAuth2JWT -JWT $NewJWT -ClientId $ClientId -ClientSecret $Token["client_secret"] -ProfileLocation $ProfileLocation -Persist:$Persist
							Write-Output -InputObject $Tok["access_token"]
						}
						else
						{
							Write-Error -Exception (New-Object -TypeName System.ArgumentException("jwt", "The stored JWT for $ClientId is not correctly formatted.")) -ErrorAction Stop
						}
					}
					else
					{
						Write-Verbose -Message "No stored tokens or jwt found for $ClientId, removing it from the cache and persisted data store."
						Remove-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation
					}
				}

				break
			}
		}
    }

    End {
    }
}

Function Update-GoogleOAuth2Token {
    [CmdletBinding(DefaultParameterSetName = "Stored")]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [ValidateNotNullOrEmpty()]
        [System.String]$RefreshToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter(DontShow = $true)]
        [ValidateSet("refresh_token")]
        [System.String]$GrantType = "refresh_token",

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$Persist
    )

    Begin {
        [System.String]$Base = "https://www.googleapis.com/oauth2/v4/token"
    }

    Process {
		Write-Verbose -Message "Updating the OAuth2 token for $ClientId."

		switch ($PSCmdlet.ParameterSetName)
		{
			"Stored" {
				# Use currently stored or cached tokens
				$TokenData = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

				if ($TokenData.ContainsKey("refresh_token") -and $TokenData.ContainsKey("client_secret"))
				{
					$ClientSecret = $TokenData["client_secret"]
					$RefreshToken = $TokenData["refresh_token"]
				}
				else
				{
					Write-Error -Exception (New-Object -TypeName System.Collections.Generic.KeyNotFoundException("The specified profile $ClientId does not contain a refresh token and/or a client secret and cannot be refreshed.")) -ErrorAction Stop
				}

				break
			}
			"Token" {
				# Do nothing
				break
			}
			default {
				Write-Error -Message "Unknown parameter set name $($PSCmdlet.ParameterSetName)." -ErrorAction Stop
			}
		}

        $ClientSecret = [System.Uri]::EscapeUriString($ClientSecret)
        $ClientId = [System.Uri]::EscapeUriString($ClientId)

        [System.String]$Url = "$Base`?client_id=$ClientId&client_secret=$ClientSecret&refresh_token=$RefreshToken&grant_type=$GrantType"

        try
        {
            [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $Url -Method Post -UserAgent PowerShell

            if ($Response.StatusCode -eq 200)
            {
				# The request was successful, convert the JSON response data
                [PSCustomObject]$Token = (ConvertFrom-Json -InputObject $Response.Content)

				# Update the local cache with the updated access token, and also possibly the refresh token if it wasn't stored originally
				# with the profile, or the profile may not have existed at all
				Set-GoogleOAuth2Profile -AccessToken $Token.access_token -RefreshToken $RefreshToken -ClientSecret $ClientSecret -ClientId $ClientId -ProfileLocation $ProfileLocation -Persist:$Persist

				# Create the hash table with the returned token
				[System.Collections.Hashtable]$Temp = @{}

				foreach ($Property in ($Token | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name))
				{
					$Temp.Add($Property, $Token.$Property)
				}

                Write-Output -InputObject $Temp
            }
            else
            {
                if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
                {
                    Write-Error -Message "There was a problem refreshing the token: $($Response.Content)" -ErrorAction Stop
                }
                else
                {
                    Write-Warning -Message "There was a problem refreshing the token: $($Response.Content)"
                }
            }
        }
        catch [System.Net.WebException] 
        {
            [System.Net.WebException]$Ex = $_.Exception
            $Stream = $Ex.Response.GetResponseStream()
            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	        [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	        $Content = $Reader.ReadToEnd()
            
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Message $Content -ErrorAction Stop
            }
            else
            {
                Write-Warning -Message $Content
            }
        }
        catch [Exception] 
        {
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
            else
            {
                Write-Warning -Message $_.Exception.Message
            }
        }
    }

    End {
    }
}

#endregion


#region JWT

Function New-GoogleServiceAccountJWT {
    <#
	
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Issuer,

        [Parameter()]
        [ValidateSet("https://www.googleapis.com/oauth2/v4/token")]
        [System.String]$Audience = "https://www.googleapis.com/oauth2/v4/token",

        [Parameter()]
        [ValidateRange(1, 3600)]
        [System.Int32]$ValidityInSeconds = 3600,

        [Parameter()]
        [System.String]$Subject
    )

	DynamicParam {
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

		$ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute
		$ParameterAttribute.Mandatory = $true
		$AttributeCollection.Add($ParameterAttribute)

		#$ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($script:Scopes)
		#$AttributeCollection.Add($ValidateSetAttribute)

		$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Scope", ([System.String[]]), $AttributeCollection)
		$RuntimeParameterDictionary.Add("Scope", $RuntimeParameter)

		return $RuntimeParameterDictionary
	}

    Begin {
        # eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
        [System.String]$JWTHeader = ConvertTo-Base64UrlEncoding -InputObject (ConvertTo-Json -InputObject @{"alg" = "RS256"; "typ" = "JWT"} -Compress)
    }

    Process {
		[System.String[]]$Scope = $PSBoundParameters["Scope"]

        [System.Int64]$Now = ([System.TimeSpan](([System.DateTime]::UtcNow) - (New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)))).TotalSeconds

        [System.Collections.Hashtable]$JWT = @{ "iss" = $Issuer; "scope" = $Scope -join " "; "aud" = $Audience; "iat" = $Now; "exp" = $Now + $ValidityInSeconds}
         
        if ($PSBoundParameters.ContainsKey("Subject") -and -not [System.String]::IsNullOrEmpty($Subject))
        {
           $JWT.Add("sub", $Subject)
        }

        $JWTClaimSet = ConvertTo-Base64UrlEncoding -InputObject (ConvertTo-Json -InputObject $JWT -Compress)

        [System.Byte[]]$SigningData = [System.Text.Encoding]::UTF8.GetBytes("$JWTHeader.$JWTClaimSet")

        [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = ConvertFrom-PEM -PEM $ClientSecret
        
        [System.Byte[]]$Sig = $RSA.SignData($SigningData, "SHA256")

        [System.String]$JWTSignature = ConvertTo-Base64UrlEncoding -Bytes $Sig

        Write-Output -InputObject "$JWTHeader.$JWTClaimSet.$JWTSignature"
    }

    End {
    }
}

#endregion


#region TokenInfo

Function Test-IsGoogleOAuth2TokenExpired {
	<#
		.SYNOPSIS
			Tests whether the provided token or token in a stored profile is expired.

		.DESCRIPTION
			This cmdlet tests a provided access token or an access token stored in a client profile to
			see whether it has expired.

			The cmdlet will by default return false if the ClientId does not exist or does not contain an access_token property. To throw
			an exception in these cases use -ErrorAction Stop.
		
		.PARAMETER AccessToken
			The token to test.

		.PARAMETER ClientId
			The id of the profile containing the access token to test. If the client profile does not
			contain an access token, this will return false, unless the ErrorActionPreference is set to
			stop, in which case an exception is thrown.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.EXAMPLE
			$Expired = Test-IsGoogleOAuth2TokenExpired -AccessToken $Token

			Tests whether the token contained in the $Token variable is expired

		.EXAMPLE
			try
			{
				$Expired = Test-IsGoogleOAuth2TokenExpired -ClientId $Id -ErrorAction Stop
			}
			catch [Exception]
			{
				Write-Host $_.Exception.Message
			}

			This example attempts to test the access token stored with the profile identified by $Id. If the profile
			is not found, or the profile doesn't contain an access token, an exception is thrown and caught in the
			catch statement.
		
		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018
	#>
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Token")]
		[ValidateNotNullOrEmpty()]
		[System.String]$AccessToken = [System.String]::Empty,

		[Parameter(Mandatory = $true, ParameterSetName = "ClientId")]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
	}

	Process {
		switch ($PSCmdlet.ParameterSetName)
		{
			"ClientId" {
				[System.Collections.Hashtable]$Token = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

				if (-not $Token.ContainsKey("access_token"))
				{
					# This will end processing
					if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
					{
						Write-Error -Exception (New-Object -TypeName System.Collections.Generic.KeyNotFoundException("There was no access token to verify for $ClientId.")) -ErrorAction Stop
					}
				}
				else
				{
					$AccessToken = $Token["access_token"]
				}

				break
			}
			"Token" {
				# Do nothing
				break
			}
			default {
				throw "Unknown parameter set $($PSCmdlet.ParameterSetName)."
			}
		}

		# This will only be null or empty if the stored item was empty
		if (-not [System.String]::IsNullOrEmpty($AccessToken))
		{
			[PSCustomObject]$TokenDetails = Get-GoogleOAuth2TokenInfo -AccessToken $AccessToken

			[System.Int64]$Exp = $TokenDetails.exp

			[System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
			[System.DateTime]$Expiration = $Epoch.AddSeconds($Exp)

			Write-Verbose -Message "The supplied access token expires $($Expiration.ToString("yyyy-MM-ddTHH:mm:ssZ"))."

			$Expired = ([System.DateTime]::UtcNow) -gt $Expiration

			Write-Output -InputObject $Expired
		}
		else
		{
			if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Error -Exception (New-Object -TypeName System.NullReferenceException("The access_token property for $ClientId was null or empty.")) -ErrorAction Stop
			}
			else
			{
				Write-Verbose -Message "There was no stored access token, returning false by default."
				Write-Output -InputObject $false
			}
		}
	}

	End {
	}
}

Function Get-GoogleOAuth2TokenInfo {
	<#
		.SYNOPSIS
			Retrieves information about an issued access token

		.DESCRIPTION
			This cmdlet retrieves information about the access token provided or contained in the client
			profile. The information includes the following details:

			azp         : 51258299791-22n6bku0cf8oln8pia505bk78l3k838e.apps.googleusercontent.com	# The ClientId
			aud         : 51258299791-22n6bku0cf8oln8pia505bk78l3k838e.apps.googleusercontent.com	# The ClientId
			scope       : https://www.googleapis.com/auth/admin.directory.group.readonly			# The requested scope in the auth code
			exp         : 1515792549																# Expiration represented by seconds past the epoch (unix timestamp)
			expires_in  : 3599																		# Seconds from now the token expires in
			access_type : offline																	# The originally requested access type

		.PARAMETER ClientId
			The id of the profile to get info on. If the ClientId 

		.PARAMETER AccessToken
			The token to retrieve details about.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.EXAMPLE
			$Details = Get-GoogleOAuth2TokenInfo -ClientId $Id

			Gets details on the access token stored with key $Id.

		.INPUTS
			None

		.OUTPUTS
			System.Collections.Hashtable

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2018
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "ClientId")]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter(Mandatory = $true, ParameterSetName = "Token")]
		[System.String]$AccessToken,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
		$Base = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	}

	Process {

		switch ($PSCmdlet.ParameterSetName)
		{
			"ClientId" {
				[System.Collections.Hashtable]$Token = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

				if (-not $Token.ContainsKey("access_token"))
				{
					Write-Error -Message "There was no access token to verify for $ClientId." -ErrorAction Stop
				}
				else
				{
					$AccessToken = $Token["access_token"]
				}

				break
			}
			"Token" {
				# Do nothing
				break
			}
			default {
				throw "Unknown parameter set $($PSCmdlet.ParameterSetName)."
			}
		}

		$Url = "$Base`?access_token=$AccessToken"

		try
		{
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Response = Invoke-WebRequest -Method Post -Uri $Url -UserAgent PowerShell

			[PSCustomObject]$Data = ConvertFrom-Json -InputObject $Response.Content

			[System.Collections.Hashtable]$Temp = @{}

			foreach ($Property in ($Data | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name))
			{
				$Temp.Add($Property, $Data.$Property)
			}

			Write-Output -InputObject $Temp
		}
        catch [System.Net.WebException] 
        {
            [System.Net.WebException]$Ex = $_.Exception
            $Stream = $Ex.Response.GetResponseStream()
            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	        [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	        $Content = $Reader.ReadToEnd()
            
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Message $Content
            }
            else
            {
                Write-Warning -Message $Content
            }
        }
        catch [Exception] 
        {
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Exception $_.Exception
            }
            else
            {
                Write-Warning -Message $_.Exception.Message
            }
        }
	}

	End {
	}
}

#endregion


#region Profile

Function Get-GoogleOAuth2Profile {
	<#
		.SYNOPSIS
			Retrieves details about a cached profile or lists all available profiles.

		.DESCRIPTION
			This cmdlet gets the tokens associated with a specific profile or lists all available profiles. Because the token data is encrypted
			using the Windows DPAPI, only token data that was stored by the current user can be successfully decrypted.

			If a specified ClientId is not found in the cache, persisted credentials are synced from disk into the cache and then it is checked again.

			If a ClientId is not specified, the cache is synced from disk and then all Ids found in the cache are returned.

			This cmdlet will only throw an exception if a ClientId is specified and not found and -ErrorAction is set to Stop, otherwise, the cmdlet
			will return null.

		.PARAMETER ClientId
			The Id of the stored profile to retrieve. If this is not specified, a list of cached profiles is returned.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.EXAMPLE
			$Profiles = Get-GoogleOAuth2Profile

			Retrieves a list of profiles cached on the system

		.EXAMPLE
			$TokenData = Get-GoogleOAuth2Profile -ClientId $Id

			Gets the unencrypted token data associated with the profile stored with Id $Id. If $Id is not found, $TokenData will be $null.

		.INPUTS
			System.String

		.OUTPUTS
			System.Collections.Hashtable or System.String[]

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2018
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable], [System.String[]])]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
		Function Convert-SecureStringToString {
            Param(
                [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
                [System.Security.SecureString]$SecureString
            )

            Begin {

            }

            Process {
                [System.String]$PlainText = [System.String]::Empty
                [System.IntPtr]$IntPtr = [System.IntPtr]::Zero

                try 
                {     
                    $IntPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)     
                    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($IntPtr)   
                }   
                finally 
                {     
                    if ($IntPtr -ne $null -and $IntPtr -ne [System.IntPtr]::Zero) 
			        {       
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($IntPtr)     
                    }   
                }

		        Write-Output -InputObject $PlainText
            }

            End {

            }
        }
	}

	Process 
	{
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		# If the client specified a specific client id, look for its data
		if ($PSBoundParameters.ContainsKey("ClientId"))
		{
			# If the cache doesn't have the client id, sync the persisted data
			if (-not $script:OAuthTokens.ContainsKey($ClientId))
			{
				Sync-GoogleOAuth2ProfileCache -ProfileLocation $ProfileLocation
			}

			# Check again to see if syncing the persisted data loaded it
			if ($script:OAuthTokens.ContainsKey($ClientId))
			{
				[System.Collections.Hashtable]$Temp = @{}

				# Need to call GetEnumerator() on a Hastable to iterate its entries
				foreach ($Property in $script:OAuthTokens[$ClientId].GetEnumerator())
				{
					if ($Property.Name -in $script:EncryptedProperties)
					{
						$Temp.Add($Property.Name, (Convert-SecureStringToString -SecureString (ConvertTo-SecureString -String $Property.Value)))
					}
					else
					{
						$Temp.Add($Property.Name, $Property.Value)
					}
				}

				Write-Output -InputObject $Temp
			}
			else
			{
				if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
				{
					# No need to write output since this will be a terminating error
					Write-Error -Exception (New-Object -TypeName System.Collections.Generic.KeyNotFoundException("The specified profile $ClientId could not be found.")) -ErrorAction Stop
				}
				else
				{
					Write-Verbose -Message "The specified profile $ClientId could not be found."
					Write-Output -InputObject $null
				}
			}
		}
		else
		{
			# Sync whatever's stored on disk first
			Sync-GoogleOAuth2ProfileCache -ProfileLocation $ProfileLocation

			# Then return the ClientIds that are used as the key identifiers in the cache
			Write-Output -InputObject ([System.String[]]($script:OAuthTokens.GetEnumerator() | Select-Object -ExpandProperty Name))
		}
	}

	End {
	}
}

Function Set-GoogleOAuth2Profile {
	<#
		.SYNOPSIS
			Sets the data in a profile.
	
		.DESCRIPTION
			This cmdlet sets data for a specified ClientId profile. The profiles support both OAuth Clients and Service Account
			based credentials. For client credentials, you must specify either an access token or refresh token. If you specify
			a refresh token, you should also specify the client secret so the token can be refreshed. 
	
			For a service account, you can store either an existing access token, or the service account private key and 
			details to construct a JWT which can be exchanged for an access token. 

		.PARAMETER ClientId
			The profile Id to store the data with, this can be an OAuth2 Client Profile or a Service Account ClientId.

		.PARAMETER ClientSecret
			The provided client secret associated with the ClientId. This can be the OAuth2 provided client secret or a private key
			from a service account.

		.PARAMETER AccessToken
			The access token to store in the profile.

		.PARAMETER RefreshToken
			The refresh token to store in the profile when using client based OAuth.

		.PARAMETER ServiceAccount
			Specifies that the client id and access token provided are for a service account.

		.PARAMETER Issuer
			The email address of the service account.

		.PARAMETER Scope
			An collection of permissions that the application requests

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.PARAMETER Persist
			Specifies if the data should be persisted to disk in an encrytped format or only maintained in the local cache (also encrypted).

		.EXAMPLE
			Set-GoogleOAuth2Profile -ClientId $Id -ClientSecret $Secret -AccessToken $Token -RefreshToken $RToken -Persist
			
			This example stores the client secret, current access token, and refresh token to the local cache and persists them to disk.

		.EXAMPLE
			Set-GoogleOAuth2Profile -ClientId $Id -ClientSecret $Secret -RefreshToken $RToken -Persist
			
			This example stores the client secret and refresh token to the local cache and persists them to disk. Because only a refresh token
			is stored, the next time the token in this profile is accessed, a new access token will be retrieved with the stored refresh token.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2018
	#>
	[CmdletBinding(DefaultParameterSetName = "client")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "client")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(ParameterSetName = "client")]
        [Parameter(ParameterSetName = "sa", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter(ParameterSetName = "client")]
		[Parameter(ParameterSetName = "sa_access_token", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$AccessToken,

        [Parameter(ParameterSetName = "client")]
        [ValidateNotNullOrEmpty()]
        [System.String]$RefreshToken,

        [Parameter(ParameterSetName = "sa", Mandatory = $true)]
		[Parameter(ParameterSetName = "sa_access_token", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServiceAccountEmail,

        [Parameter(ParameterSetName = "sa", DontShow = $true)]
        [ValidateSet("https://www.googleapis.com/oauth2/v4/token")]
        [System.String]$Audience = "https://www.googleapis.com/oauth2/v4/token",

        [Parameter(ParameterSetName = "sa")]
        [ValidateRange(1, 3600)]
        [System.Int32]$ValidityInSeconds = 3600,

        [Parameter(ParameterSetName = "sa")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Subject,

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$Persist
	)

	DynamicParam {
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

		$ParameterAttribute = New-Object -TypeName System.Management.Automation.PARAMETERAttribute
		$ParameterAttribute.Mandatory = $true
		$ParameterAttribute.ParameterSetName = "sa"
		$AttributeCollection.Add($ParameterAttribute)

		$ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($script:Scopes)
		$AttributeCollection.Add($ValidateSetAttribute)

		$RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Scope", ([System.String[]]), $AttributeCollection)
		$RuntimeParameterDictionary.Add("Scope", $RuntimeParameter)

		return $RuntimeParameterDictionary
	}

	Begin {
	}

	Process {		
		if ($PSCmdlet.ParameterSetName -ilike "sa*")
		{
			$ClientId = $ServiceAccountEmail
		}

		Write-Verbose -Message "Setting profile $ClientId."

		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		# Create the profile store if it doesn't exist
		if (-not (Test-Path -Path $ProfileLocation))
        {
            New-Item -Path $ProfileLocation -ItemType File -Force | Out-Null
        }

		# This will hold the data supplied by the parameters for the token information to store
		# Use a hashtable so it's easy to check property existence
		[System.Collections.Hashtable]$Profile = @{}

        if ($PSBoundParameters.ContainsKey("ClientSecret"))
		{
			if ($PSCmdlet.ParameterSetName -eq "sa")
			{
				$ClientSecret = $ClientSecret.Replace("\n", "").Replace("\r", "").Replace("`r", "").Replace("`n", "")
			}

		    $Profile.Add("client_secret", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)))
		}

        # Mandatory so we know what type of credentials these are
        if ($PSCmdlet.ParameterSetName -ilike "sa*")
		{
            $Profile.Add("type", "sa")
        }
        else
        {
		    $Profile.Add("type", "client")
        }

        switch ($PSCmdlet.ParameterSetName)
        {
            "sa_access_token" {
                if ($PSBoundParameters.ContainsKey("AccessToken"))
			    {
				    $Profile.Add("access_token", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $AccessToken -AsPlainText -Force)))
			    }

                break
            }
            "sa" {
				[System.String[]]$Scope = $PSBoundParameters["Scope"]

				[System.String[]]$FinalScopes = @()

				foreach ($Item in $Scope)
				{
					if ($Item -notin $script:NoUrlScopes)
					{
						$FinalScopes += "https://www.googleapis.com/auth/$Item"
					}
					elseif ($Item -eq "cloud-platform-service-control")
					{
						# cloud-platform is used both with a preceding url for some services and without for cloud service control APIs
						$FinalScopes += "cloud-platform"
					}
					else
					{
						$FinalScopes += $Item
					}
				}

				$JWT = New-GoogleServiceAccountJWT -ClientSecret $ClientSecret -Issuer $ServiceAccountEmail -Scope $FinalScopes -ValidityInSeconds $ValidityInSeconds -Subject $Subject

                $Profile.Add("jwt", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $JWT -AsPlainText -Force)))

                break
            }
            "client" {

                if (-not $PSBoundParameters.ContainsKey("AccessToken") -and -not $PSBoundParameters.ContainsKey("RefreshToken"))
                {
                    Write-Error -Exception (New-Object -TypeName System.ArgumentException("At least AccessToken or RefreshToken must be specified for the Set-GoogleOAuth2Profile cmdlet when specifying OAuth client information.")) -ErrorAction Stop
                }

                if ($PSBoundParameters.ContainsKey("AccessToken"))
			    {
				    $Profile.Add("access_token", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $AccessToken -AsPlainText -Force)))
			    }
				
			    if ($PSBoundParameters.ContainsKey("RefreshToken"))
			    {
				    $Profile.Add("refresh_token", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $RefreshToken -AsPlainText -Force)))
			    }

                break
            }
			default {
				Write-Error -Message "Unknown parameter set $($PSCmdlet.ParameterSetName)." -ErrorAction Stop
			}
        }

		# If the profile already exists in the cache, update the information, don't worry about checking to see if it's
		# different since it's not a big penalty to rewrite to memory		
        if ($script:OAuthTokens.ContainsKey($ClientId))
        {
			foreach ($Property in $Profile.GetEnumerator())
			{
				if ($script:OAuthTokens[$ClientId].ContainsKey($Property.Name))
				{
					$script:OAuthTokens[$ClientId][$Property.Name] = $Property.Value
				}
				else
				{
					$script:OAuthTokens[$ClientId].Add($Property.Name, $Property.Value)
				}
			}
        }
        else
        {
			$script:OAuthTokens.Add($ClientId, $Profile)
        }

		# If the profile is being persisted, merge it with the saved profile data
		if ($Persist)
		{
			# Let's make sure the tokens were different before we decide to write something back to disk
			[System.Boolean]$ChangeOccured = $false

			[PSCustomObject]$ProfileData = [PSCustomObject]@{}

			[System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

			# This will load the persisted data from disk into the cache object
			if (-not [System.String]::IsNullOrEmpty($Content))
			{
				[PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content
			}

			# This could happen if the credential file just contains whitespace and no content
			# Use this approach since the ProfileData is a PSCustomObject
			if ($ProfileData -ne $null -and (Get-Member -InputObject $ProfileData -Name $ClientId -MemberType Properties) -ne $null) 
			{
				Write-Verbose -Message "The profile $ClientId may be overwritten with new data."
				
				[System.String[]]$EncryptedProperties = @("access_token", "refresh_token", "client_secret", "jwt")

				foreach ($Property in $script:EncryptedProperties)
				{
					if ($Profile.ContainsKey($Property))
					{
						if (($ProfileData.$ClientId | Get-Member -Name $Property -MemberType Properties) -ne $null)
						{
							# Since the DPAPI uses a time factor to generate the encryption, the encrypted data is different
							# each time the encryption is performed, convert the encrypyted string to a secure string
							# in order to compare them successfully
							if (
								[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $ProfileData.$ClientId.$Property))) -ne
								[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Profile[$Property])))
							)
							{
								$ProfileData.$ClientId.$Property = $Profile[$Property]
							
								# Note that an update actually happened
								$ChangeOccured = $true
							}
						}
						else
						{
							$ProfileData.$ClientId | Add-Member -MemberType NoteProperty -Name $Property -Value $Profile[$Property]
						
							# Note that an update actually happened
							$ChangeOccured = $true
						}					
					}
				}
			}
			else 
			{
				$ProfileData | Add-Member -MemberType NoteProperty -Name $ClientId -Value $Profile

				# Note that an update actually happened
				$ChangeOccured = $true
			}

			# It's possible no updates were actually made to the existing data, only write to disk if a change
			# was made

			if ($ChangeOccured)
			{
				Set-Content -Path $ProfileLocation -Value (ConvertTo-Json -InputObject $ProfileData) -Force

				Write-Verbose -Message "Successfully persisted profile data for $ClientId in $ProfileLocation."
			}
			else
			{
				Write-Verbose -Message "No profile data changes occured for persisted data, nothing updated on disk."
			}
		}
		
		Write-Verbose -Message "Successfully created or updated the profile for $ClientId"
	}

	End {
	}
}

Function Remove-GoogleOAuth2Profile {
	<#
		.SYNOPSIS
			Removes a cached and/or stored Google OAuth profile.

		.DESCRIPTION
			This cmdlet will delete the cached and stored profile for the specified client id. If RevokeToken is specified, the set of tokens,
			including the refresh token will be invalidated.

		.PARAMETER ClientId
			The supplied client id for OAuth.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.PARAMETER RevokeToken
			This specifies that any tokens associated with this profile will be revoked permanently.

		.PARAMETER PassThru
			If this is specified, the deleted profile data is returned to the pipeline.

		.EXAMPLE
			Remove-GoogleOAuth2Profile -ClientId $Id 

			Removes cached and persisted profile data for the id contained in the $Id variable. The user is prompted before the removal occurs.

		.EXAMPLE
			Remove-GoogleOAuth2Profile -ClientId $Id -RevokeToken -Force
			
			Removes cached and persisted profile data for the id contained in the $Id variable and invalidates all associated tokens that have been issued. The
			-Force parameter bypasses any confirmation.

		.INPUTS
			None

		.OUTPUTS
			None or System.Collections.Hashtable

			The hashtable will contain either an access_token or refresh_token property or both.

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018		
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$RevokeToken,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[Switch]$PassThru
	)

	Begin {
	}

	Process {
		Write-Verbose -Message "Removing profile $ClientId."

		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		# Do this before we delete it from the cache so we don't have to go to disk
		[System.Collections.Hashtable]$Profile = Get-GoogleOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation -ErrorAction SilentlyContinue

		if ($script:OAuthTokens.ContainsKey($ClientId))
		{
			$script:OAuthTokens.Remove($ClientId)
		}
		else
		{
			Write-Verbose -Message "Not profile data for $ClientId found in the cache."
		}

        [System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

		# This will load the persisted data from disk into the cache object
        if (-not [System.String]::IsNullOrEmpty($Content))
		{
			[PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content

			# The profile contains the clientId to remove
			if ($Profile -ne $null)
			{
				$ConfirmMessage = "You are about to delete profile $ClientId. If you specified -RevokeToken, the REFRESH TOKEN will be revoked and you will need to submit a new authorization code to retrieve a new token."
				$WhatIfDescription = "Deleted profile $ClientId"
				$ConfirmCaption = "Delete Google OAuth2 Profile"

				if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
				{
					if ($RevokeToken)
					{
						$Token = ""

						if ($Profile.ContainsKey("access_token"))
						{
							$Token = $Profile["access_token"]
						}
						elseif ($Profile.ContainsKey("refresh_token"))
						{
							$Token = $Profile["refresh_token"]
						}
						else
						{
							Write-Warning -Message "RevokeToken was specified, but no tokens are associated with the profile $ClientId."
						}

						if (-not [System.String]::IsNullOrEmpty($Token))
						{
							try
							{
								[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri "https://accounts.google.com/o/oauth2/revoke?token=$Token" -Method Post -UserAgent PowerShell

								if ($Response.StatusCode -ne 200)
								{
									Write-Warning -Message "There was a problem revoking the access token associated with $ClientId."
								}
							}
							catch [System.Net.WebException] 
							{
								[System.Net.WebException]$Ex = $_.Exception
								$Stream = $Ex.Response.GetResponseStream()
								[System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
								[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
								$Content = $Reader.ReadToEnd()
            
								if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
								{
									Write-Error -Message $Content
								}
								else
								{
									Write-Warning -Message $Content
								}
							}
							catch [Exception] 
							{
								if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
								{
									Write-Error -Exception $_.Exception
								}
								else
								{
									Write-Warning -Message $_.Exception.Message
								}
							}
						}
					}


					# This returns void, so do it first, then pass the ProfileData variable
					$ProfileData.PSObject.Properties.Remove($ClientId)

					$Value = ""

					if (($ProfileData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name).Count -gt 0)
					{
						$Value = (ConvertTo-Json -InputObject $ProfileData)
					}

					if ([System.String]::IsNullOrEmpty($Value))
					{
						Clear-Content -Path $ProfileLocation -Force
					}
					else
					{
						Set-Content -Path $ProfileLocation -Value $Value -Force
					}

					Write-Verbose -Message "Successfully removed profile $ClientId."

					if ($PassThru) 
					{
						Write-Output -InputObject $Profile
					}
				}
			}
			else
			{
				Write-Error -Message "No profile matching $ClientId in $ProfileLocation."
			}
		}
		else
		{
			Write-Verbose -Message "No persisted profile data found in $ProfileLocation."
		}
	}

	End {
	}
}

Function Sync-GoogleOAuth2ProfileCache {
	<#
		.SYNOPSIS
			Syncs the stored profile data with the in memory cache.

		.DESCRIPTION
			This cmdlet loads the data stored in local credential file into the in-memory cache of credentials.

			You typically will not need to call this cmdlet, the other cmdlets that use the profile data will call this on your behalf.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.EXAMPLE
			Sync-GoogleOAuth2ProfileCache

			This syncs the locally stored profile data to the in-memory cache.

		.INPUTS 
			None

		.OUTPUTS
			None
		
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018	
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		[System.Boolean]$AddedToCache = $false

		Write-Verbose -Message "Syncing data from $ProfileLocation into local cache."

        [System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

		# This will load the persisted data from disk into the cache object
        if (-not [System.String]::IsNullOrEmpty($Content))
		{
		    [PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content

            # Iterate each key value in the PSCustomObject which represents a ClientId
            foreach ($Property in ($ProfileData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) 
            {
                # If the module cache of profiles doesn't contain a token for the persisted client id, add it
                if (-not $script:OAuthTokens.ContainsKey($Property))
                {
					Write-Verbose -Message "Adding data for $Property into local cache from disk."
					$AddedToCache = $true

                    $script:OAuthTokens.Add($Property, @{})

					foreach ($Token in ($ProfileData.$Property | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name))
					{
						# Add the token values to the cache
						$script:OAuthTokens[$Property].Add($Token, $ProfileData.$Property.$Token)
					}
                }
            }

			if (-not $AddedToCache)
			{
				Write-Verbose -Message "No updates required to the profile cache."
			}
		}
		else
		{
			Write-Verbose -Message "No persisted profile data found in $ProfileLocation."
		}
	}

	End {
	}
}

#endregion