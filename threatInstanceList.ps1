function Get-SecurityAPISession {
	param (
		[Parameter(Mandatory)]
		$domain,
		
		[Parameter(Mandatory)]
    [PSCredential]
		$Credential
	)

	$tidResponse = Invoke-RestMethod -UseBasicParsing -Uri "https://login.windows.net/$domain/FederationMetadata/2007-06/FederationMetadata.xml"
	$tid = ([regex]'entityID="(.+?)"').matches($tidResponse).Groups[1].value.Replace("https://sts.windows.net/", "").replace('/','')
	$configJsonRegex = [regex]'Config=(.+?});'

	try {
		$uri = "https://security.microsoft.com/threatexplorerv3?tid=$tid"
		
		# https://github.com/rchaganti/PSGitIo/issues/1
		# resolves powershell 6+
		$response = Invoke-WebRequest -UseBasicParsing -Uri $uri -SessionVariable WebSession -MaximumRedirection 0 -ErrorAction SilentlyContinue -ErrorVariable redirected
		
		$authorizeUri = $response.Headers.Location.ToString()		
	} 
	catch {
		 $authorizeUri = $redirected.ErrorRecord.Exception.Response.Headers.Location.ToString()
	}
	
	try {
		$uri = $authorizeUri
		$authorizationResponse = Invoke-WebRequest -UseBasicParsing -Uri $uri -WebSession $WebSession
	}
	catch {
		throw $_.Exception
	}

	$hpgrequestid = $authorizationResponse.Headers['x-ms-request-id']
	$authorizationConfig = $configJsonRegex.matches($authorizationResponse.Content).Groups[1].value | ConvertFrom-Json
	
	$loginPost = "https://login.microsoftonline.com" + $authorizationConfig.urlPost
	
	# Login to login.microsoftonline.com
	$loginBody = @{
		canary 			      = $authorizationConfig.canary
		CookieDisclosure  = '0'
		ctx				        = $authorizationConfig.sCtx
		flowToken 		    = $authorizationConfig.sFT
		FoundMSAs 		    = $null
		fspost 			      = '0'
		hisRegion 		    = $null
		hisScaleUnit 	    = $null
		hpgrequestid 	    = $hpgrequestid
		i13  			        = '0'
		i19 			        = '17313'
		i21 			        = '0'
		IsFidoSupported   = '1'
		isSignupPost 	    = '0'
		login 			      = $Credential.userName
		loginfmt 		      = $Credential.userName
		LoginOptions 	    = '3'
		lrt 			        = $null
		lrtPartition 	    = $null
		NewUser 		      = '1'
		passwd 			      = $Credential.GetNetworkCredential().Password
		PPSX			        = $null
		ps   			        = '2'
		psRNGCDefaultType = $null
		psRNGCEntropy 	  = $null
		psRNGCSLK 		    = $null
		type 			        = '11'
	}

	$loginHeaders = @{
		'Sec-Fetch-Dest' = 'document'
		'Sec-Fetch-Site' = 'same-origin'
		'Sec-Fetch-Mode' = 'navigate'
		'Referer'		 = $authorizeUri
	}

	try {
		$uri = $loginPost
		$loginResponse = Invoke-WebRequest -UseBasicParsing -Uri $uri `
		-Method POST `
		-Headers $loginHeaders `
		-Body $loginBody `
		-WebSession $WebSession `
		-ErrorAction Ignore
	}
	catch {
		throw $_.Exception.response
	}
	
	$loginConfig = $configJsonRegex.matches($loginResponse.Content).Groups[1].value | ConvertFrom-Json

	# Keep Me Signed In? yes

	$kmsiHeaders = @{
		'Sec-Fetch-Dest' = 'document'
		'Sec-Fetch-Site' = 'same-origin'
		'Sec-Fetch-Mode' = 'navigate'
		'Referer'		     = $loginPost
	}

	$kmsiBody = @{
		canary       = $loginConfig.canary
		ctx          = $loginConfig.sCtx
		flowToken    = $loginConfig.sFT
		hpgrequestid = $loginConfig.sessionId
		i19          = 3752 # no=2018, yes=1
		LoginOptions = 1	# no=3,    yes=1
		type         = 28
	}

	try {
		$kmsiResponse = Invoke-WebRequest -UseBasicParsing -Uri 'https://login.microsoftonline.com/kmsi' `
		-Method POST `
		-Headers $kmsiHeaders `
		-ContentType "application/x-www-form-urlencoded" `
		-Body $kmsiBody `
		-WebSession $WebSession
	}
	catch {
		throw $_.Exception.response
	}
	
	$securityBody = @{}
	$kmsiResponse.InputFields.where({$_.type -eq 'hidden'}) | foreach {
		$securityBody.($PSItem.Name) = $PSItem.value
	}

	$WebSession.Cookies.MaxCookieSize=65536

	$securityHeaders = @{
		"authority"='security.microsoft.com'
		"method"='POST'
		"path"='/'
		"scheme"='https'
		"accept"='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
		"accept-encoding"='gzip, deflate, br'
		"accept-language"='en-US,en;q=0.9'
		"cache-control"="max-age=0"
		"origin"="https://login.microsoftonline.com"
		"referer"="https://login.microsoftonline.com/"
		"sec-fetch-dest"="document"
		"sec-fetch-mode"="navigate"
		"sec-fetch-site"="cross-site"
		"upgrade-insecure-requests"="1"
	}

	try {
		$securityResponse = Invoke-WebRequest -UseBasicParsing -Uri "https://security.microsoft.com/" `
		-Method POST `
		-Headers $securityHeaders `
		-ContentType "application/x-www-form-urlencoded" `
		-Body $securityBody `
		-UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" `
		-WebSession $WebSession `
		-MaximumRedirection 1
	}
	catch {
		throw $_.Exception.response
	}
	
	$sccauth = $WebSession.Cookies.GetAllCookies().where({$_.name -eq 'sccauth'})
	$xsrfToken = $WebSession.Cookies.GetAllCookies().where({$_.name -eq 'XSRF-TOKEN'})
	
	@{
		tid=$tid;
		xsrf=$xsrfToken;
		webSession=$WebSession
	}
}

function invoke-ThreatInstanceList {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]$authSession,
		[Parameter(Mandatory=$true)]$body,
		[Parameter(Mandatory=$false)]$StartPage = 1,
	
		[parameter(Mandatory=$true,HelpMessage="[DateTime]::UtcNow.AddDays(-`$days)")]
		[datetime]$FromDateTime=$null,
		[parameter(Mandatory=$true,HelpMessage="[DateTime]::UtcNow")]
		[datetime]$ToDateTime=$null
	)
	
	$tid = $authSession.tid
	$xsrfToken = $authSession.xsrf
	$WebSession = $authSession.webSession
	
	if ( ($ToDateTime - $FromDateTime).TotalDays -gt 29) {
		throw 'ThreatExplorer does not go back more than 29 days'
	}
	
	$Headers= @{
		"Accept"="application/json, text/plain, */*"
		"X-XSRF-TOKEN" = [System.Net.WebUtility]::UrlDecode($xsrftoken.value)
		"Origin" = "https://security.microsoft.com"
		"Referer" = "https://security.microsoft.com/threatexplorerv3?tid=$tid"
		"Sec-Fetch-Dest" = "empty"
		"Sec-Fetch-Mode" = "cors"
		"Sec-Fetch-Site" = "same-origin"
	}

	$ContentType = "application/x-www-form-urlencoded"
	
	$url = "https://security.microsoft.com/apiproxy/di/Aggregate/ThreatInstanceList?tenantid=$tid"

	
	if ($StartPage -ge 2) {
		$body.StartPage =  $StartPage
	}

	$json = $body | ConvertTo-Json -Depth 3
	
	try {
		$threatInstanceListResponse = Invoke-WebRequest -UseBasicParsing -Uri $url `
		-Method POST `
		-WebSession $WebSession `
		-UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" `
		-Headers $Headers `
		-ContentType $ContentType `
		-Body $json
		
		$threatInstanceList = $threatInstanceListResponse.Content | ConvertFrom-Json
		
		$threatInstanceList
		
		# if more pages then increment "StartPage by 1"
		if ($threatInstanceList.resultdata.MorePages) {
			$StartPage++

			invoke-ThreatInstanceList -authSession $authSession -body $body -StartPage $StartPage -FromDateTime $FromDateTime -ToDateTime $ToDateTime
		}
		
	}
	catch {
		throw $_.Exception.response
	}
}

function Get-MaliciousEmailsRemovedAfterDelivery {
	param (
		[Parameter(Mandatory=$true)]$authSession,
	
		[parameter(Mandatory=$true,HelpMessage="[DateTime]::UtcNow.AddDays(-`$days)")]
		[datetime]$FromDateTime=$null,
		
		[parameter(Mandatory=$true,HelpMessage="[DateTime]::UtcNow")]
		[datetime]$ToDateTime=$null
	)

	$ThreatIntelSessionContext =
		[pscustomobject][ordered]@{
			UseSessionCookie = $true
			UseScrollPagination = $false
			PaginationCookie = $null
			SessionCookie = 'o365ipdinam11-esd-nu-04.northcentralus.cloudapp.azure.com'
		}

	# Original Delivery = Inbox, Latest Delivery = Quarantine
	$TextSearchFilters =
		[pscustomobject][ordered]@{
			FieldName = 'DeliveryLocationCode'
			FilterText = @(1)
		},
		[pscustomobject][ordered]@{
			FieldName = 'CurrentDeliveryLocationCode'
			FilterText = @(4)
		}
	
	$strFromDateTime = $FromDateTime.ToString('s')
	$strToDateTime = $ToDateTime.ToString('s')
	
	# ThreatExplorer does not go back more than 29 days
	$body = @{
		StartTime = $strFromDateTime # [datetime]"2024-01-29T08:00:00.000Z"
		EndTime = $strToDateTime # [datetime]"2024-02-03T07:59:59.000Z"
		PageSize = [long]50
		ThreatType = [long]2
		ThreatIntelSessionContext = $ThreatIntelSessionContext
		Kql = '( (DeliveryLocationCode=1) AND (CurrentDeliveryLocationCode=4)) AND (ContentType:1)'
		TextSearchFilters = $TextSearchFilters
		ProtectionStatusFilter = @()
	}
	
	invoke-ThreatInstanceList -authSession $authSession -body $body -FromDateTime $FromDateTime -ToDateTime $ToDateTime
}
