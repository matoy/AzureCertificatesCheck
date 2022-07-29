using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

#####
#
# TT 20220617 AzureCertificatesCheck
# This script is executed by an Azure Function App
# It checks if there are some expiring certificates in a specific resources
#
# It can be triggered by any monitoring system to get the results and status
#
# "mode" GET parameter allows to specify to search the whole subscription, 
# or a specific application gateway or webapp.
# possible values are : subscription, appgw, webapp
#
# if mode=subscription (default): 
# "subscriptionid" GET parameter must be specified
# "exclusion" GET parameter can be passed with comma separated resource names
# that should be excluded from the check
#
# if mode=appgw : 
# "subscriptionid" GET parameter must be specified
# "appGwName" GET parameter must be specified
#
# if mode=webapp : 
# "subscriptionid" GET parameter must be specified
# "webAppName" GET parameter must be specified
#
# if mode=keyvault : 
# "subscriptionid" GET parameter must be specified
# "kvName" GET parameter must be specified
#
# warning and critical thresholds can be passed in the GET parameters
# and are expressed in days before expiry (default 40 and 20)
#
# used AAD credentials read access to the specified subscription
#
#
#####

$exclusion = [string] $Request.Query.exclusion
if (-not $exclusion) {
    $exclusion = ""
}

$subscriptionid = [string] $Request.Query.Subscriptionid
if (-not $subscriptionid) {
    $subscriptionid = "00000000-0000-0000-0000-000000000000"
}

$mode = [string] $Request.Query.mode
if (-not $mode) {
    $mode = "subscription"
}

$appGwName = [string] $Request.Query.appGwName
if (-not $appGwName) {
    $appGwName = $null
}

$webAppName = [string] $Request.Query.webAppName
if (-not $webAppName) {
    $webAppName = $null
}

$kvName = [string] $Request.Query.kvName
if (-not $kvName) {
    $kvName = $null
}

$warning = [int] $Request.Query.Warning
if (-not $warning) {
    $warning = 40
}

$critical = [int] $Request.Query.Critical
if (-not $critical) {
    $critical = 20
}

# init variables
$signature = $env:Signature
[System.Collections.ArrayList] $exclusionsTab = $exclusion.split(",")
foreach ($current in ($env:AzureCertificatesCheckGlobalExceptions).split(",")) {
	$exclusionsTab.Add($current)
}
$datecheckWarning = (get-date).adddays($warning)
$datecheckCritical = (get-date).adddays($critical)
$statusOutput = ""
$statusCode = 0
$alertNumber = 0
$okNumber = 0

# connect with SPN account creds
$tenantId = $env:TenantId
$applicationId = $env:AzureCertificatesCheckApplicationID
$password = $env:AzureCertificatesCheckSecret
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $applicationId, $securePassword
Connect-AzAccount -Credential $credential -Tenant $tenantId -ServicePrincipal

# get token
$azContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)

# create http headers
$headers = @{}
$headers.Add("Authorization", "bearer " + "$($Token.Accesstoken)")
$headers.Add("contenttype", "application/json")

Try {
	if ($mode -eq "subscription" -or $mode -eq "appgw") {
		$apiversion = "2021-08-01"
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Network/applicationGateways?api-version=$apiversion"
		if ($mode -eq "appgw" -and $appGwName) {
			$appgws = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$_.name -eq $appGwName}
		}
		else {
			$appgws = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$exclusionsTab -notcontains $_.name}
		}
		foreach ($appgw in $appgws) {
			$uri = "https://management.azure.com$($appgw.id)?api-version=$apiversion"
			$results = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

			foreach ($certificate in $results.properties.sslCertificates) {
				if ($certificate.properties.provisioningState -ne "Succeeded" -or !$certificate.properties.publicCertData) {
					continue
				}
				$certBytes = [Convert]::FromBase64String($certificate.properties.publicCertData)
				$p7b = New-Object System.Security.Cryptography.Pkcs.SignedCms
				$p7b.Decode($certBytes)
				$x509 = $p7b.Certificates[0]
				#$x509 | fl
				$timeDiff = (New-TimeSpan -Start (Get-Date) -End $x509.NotAfter).Days
				if ($timeDiff -le 0) {
					$statusOutput = "CRITICAL: AppGw $($results.name) - Listener $($certificate.name) certificate has expired $([Math]::Abs($timeDiff)) day(s) ago on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckCritical -gt $x509.NotAfter) {
					$statusOutput = "CRITICAL: AppGw $($results.name) - Listener $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckWarning -gt $x509.NotAfter) {
					$statusOutput = "WARNING: AppGw $($results.name) - Listener $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					if ($statusCode -eq 0) { $statusCode = 1 }
				}
				else {
					$okNumber++
					$statusOutput += "OK: AppGw $($results.name) - Listener $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n"
				}
			}

			foreach ($certificate in $results.properties.authenticationCertificates) {
				if ($certificate.properties.provisioningState -ne "Succeeded" -or !$certificate.properties.backendHttpSettings) {
					continue
				}
				$certBytes = [Convert]::FromBase64String($certificate.properties.data)
				$x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certbytes)
				#$x509 | fl
				$timeDiff = (New-TimeSpan -Start (Get-Date) -End $x509.NotAfter).Days
				if ($timeDiff -le 0) {
					$statusOutput = "CRITICAL: AppGw $($results.name) - Backend $($certificate.name) certificate has expired $([Math]::Abs($timeDiff)) day(s) ago on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckCritical -gt $x509.NotAfter) {
					$statusOutput = "CRITICAL: AppGw $($results.name) - Backend $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckWarning -gt $x509.NotAfter) {
					$statusOutput = "WARNING: AppGw $($results.name) - Backend $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					if ($statusCode -eq 0) { $statusCode = 1 }
				}
				else {
					$okNumber++
					$statusOutput += "OK: AppGw $($results.name) - Backend $($certificate.name) certificate expires in $timeDiff day(s) on $($x509.NotAfter.ToString("dd/MM/yyyy"))`n"
				}
			}
		}
	}

	if ($mode -eq "subscription" -or $mode -eq "webapp") {
		$apiversion = "2021-02-01"
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Web/sites?api-version=$apiversion"
		if ($mode -eq "webapp" -and $webAppName) {
			$webapps = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$_.name -eq $webAppName}
		}
		else {
			$webapps = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$exclusionsTab -notcontains $_.name}
		}	
		if ($webapps.count -ne 0) {
			$uri = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.Web/certificates?api-version=$apiversion"
			$webappcertificates = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value
		}
		foreach ($webapp in $webapps) {
			foreach ($cert in $webapp.properties.hostNameSslStates) {
				if ($cert.thumbprint) {
					$certs = $webappcertificates.properties | where {$_.thumbprint -eq $cert.thumbprint}
					$expiryDate = $certs[0].expirationDate
					$timeDiff = (New-TimeSpan -Start (Get-Date) -End $expiryDate).Days
					if ($timeDiff -le 0) {
						$statusOutput = "CRITICAL: WebApp $($webapp.name) $($cert.name) certificate has expired $([Math]::Abs($timeDiff)) day(s) ago on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
						$alertNumber++
						$statusCode = 2
					}
					elseif ($datecheckCritical -gt $expiryDate) {
						$statusOutput = "CRITICAL: WebApp $($webapp.name) $($cert.name) certificate expires in $timeDiff day(s) on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
						$alertNumber++
						$statusCode = 2
					}
					elseif ($datecheckWarning -gt $expiryDate) {
						$statusOutput = "WARNING: WebApp $($webapp.name) $($cert.name) certificate expires in $timeDiff day(s) on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
						$alertNumber++
						if ($statusCode -eq 0) { $statusCode = 1 }
					}
					else {
						$okNumber++
						$statusOutput += "OK: WebApp $($webapp.name) $($cert.name) certificate expires $([Math]::Abs($timeDiff)) day(s) ago on $($expiryDate.ToString("dd/MM/yyyy"))`n"
					}
				}
			}
		}
	}
	
	#this is executed only in keyvault mode, not subscription mode because of the need to apply RBAC permission on every KV data plane.
	if ($mode -eq "keyvault") {
		$apiversion = "2021-10-01"
		$uri = "https://management.azure.com/subscriptions/$subscriptionid//providers/Microsoft.KeyVault/vaults?api-version=$apiversion"
		if ($mode -eq "keyvault" -and $kvName) {
			$kvs = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$_.name -eq $kvName}
		}
		else {
			$kvs = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value | where {$exclusionsTab -notcontains $_.name}
		}
		if ($kvs.count -ne 0) {
			$uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
			$vaultCreds = @{
				'client_id' = $applicationId
				'client_secret' = $password
				'scope' = "https://vault.azure.net/.default"
				'grant_type' = "client_credentials"
			}
			$vaultToken = (Invoke-RestMethod -Method Post -Uri $uri -Body $vaultCreds -ContentType 'application/x-www-form-urlencoded')
			$vaultHeaders = @{}
			$vaultHeaders.Add("Authorization", "bearer " + "$($vaultToken.access_token)")
			$vaultHeaders.Add("contenttype", "application/json")
			$origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
		}
		foreach ($kv in $kvs) {
			$apiversion = "7.3"
			$uri = "$($kv.properties.vaultUri)certificates?api-version=$apiversion"
			$results = (Invoke-RestMethod -Method Get -Uri $uri -Headers $vaultHeaders).value
			echo "$($kv.name)"

			foreach ($certificate in $results) {
				if ($certificate.attributes.enabled -ne "True") {
					continue
				}
				$expiryDate = $origin.AddSeconds($certificate.attributes.exp)
				$timeDiff = (New-TimeSpan -Start (Get-Date) -End $expiryDate).Days
				$name = $certificate.id.Split("/")[-1]
				echo "$name"
				if ($timeDiff -le 0) {
					$statusOutput = "Keyvault $($kv.name) $.name certificate has expired $([Math]::Abs($timeDiff)) day(s) ago on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckCritical -gt $expiryDate) {
					$statusOutput = "Keyvault $($kv.name) $name certificate expires in $timeDiff day(s) on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					$statusCode = 2
				}
				elseif ($datecheckWarning -gt $expiryDate) {
					$statusOutput = "Keyvault $($kv.name) $name certificate expires in $timeDiff day(s) on $($expiryDate.ToString("dd/MM/yyyy"))`n" + $statusOutput
					$alertNumber++
					if ($statusCode -eq 0) { $statusCode = 1 }
				}
				else {
					$okNumber++
					$statusOutput += "OK: Keyvault $($kv.name) $name certificate expires in $timeDiff day(s) on $($expiryDate.ToString("dd/MM/yyyy"))`n"
				}
			}
		}
	}

	if ($statusCode -eq 2) {
		$body = "CRITICAL: $alertNumber certificate alert(s)`n" + $statusOutput
	}
	elseif ($statusCode -eq 1) {
		$body = "WARNING: $alertNumber certificate alert(s)`n" + $statusOutput
	}
	else {
		$body = "OK: $okNumber certificate(s) fine`n" + $statusOutput
	}
}
Catch {
    if($_.ErrorDetails.Message) {
		$msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error
		$body = "CRITICAL: " + $msg.code + ": " + $msg.message + "`n"
    }
}

Write-Host $body

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
