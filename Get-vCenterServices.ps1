<#
.SYNOPSIS
This PowerShell script allows you to quickly check the status of vCenter Services.

.DESCRIPTION
The script interacts with the REST based vSphere APIs (cis,vcenter,appliance) 
in order to list the status of vCenter Services.  When run, it tries to authenticate 
against cis API with the given credentials. If the session is established successfully, 
a token is acquired and a simple menu is presented in order to trigger other functions 
to retrieve the status of vCSA Services by performing REST calls towards the appliance API.

.NOTES  
Created by:  Ioannis Patsiotis
Email: ioannis.patsiotis@gmail.com
Date Created: 02/11/2019
Version: 1.1
Dependencies: vCenter Appliance 6.5 (6.5.0.15000) and higher

===Tested Against Environment====
vCSA Version: vCenter Appliance 6.7 U2 (6.7.0.30000)
vCSA Version: vCenter Appliance 6.5 (6.5.0.15000)
PowerCLI Version: PowerCLI 6.5 R1
PowerShell Version: 5.1
OS Version: Windows 10 1903

.EXAMPLE
.\Get-vCenterServices.ps1
#>


#Function to visualize the menu
function Show-Menu {
    param (
           [string]$Title = 'VMware vCenter Server Appliance - Services Monitoring'
    )
    
    cls
    Write-Host "================ $Title ================" 

    Write-Host "1: Press '1' to list details of all VMware vCSA services."
    Write-Host "2: Press '2' to list the services managed by vmware-vmon (VMware Service Lifecycle Manager) service."
    Write-Host "3: Press '3' to list version information about the VMware vCSA.`n"

    Write-Host "================ EXIT ================" 
    Write-Host "Q: Press 'Q' to quit.`n"
}

#Function to convert the given credentials to Base64 encode
function Set-Credentials {
    param (
       [Parameter(Mandatory=$true)][string]$username,
       [Parameter(Mandatory=$true)][string]$password
    )
    
    $pair = "${username}:${password}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
 
    $basicAuthValue = "Basic $base64"
    return $basicAuthValue
}

#Function to request session id
function Create-Session {

	Ignore-Certificate
	$responsesessionid = Invoke-vCenterTokenRequest -Uri $RestApiUrl/com/vmware/cis/session -method "POST"
	
    return $responsesessionid
}

#Function to create session id
function Invoke-vCenterTokenRequest {
    param (
        [string]$uri=$REST_URL,
        [string]$method,
        [string]$body=$null
    )
    
    $headers = @{
        'authorization' =  $creds;
        'content-type' =  'application/json';
        'Accept' = 'application/json';
        
    }
    $response = Invoke-RestMethod -uri $uri -Headers $headers -Method $method -Body $body 
    
    return $response
}

#Function to ignore vCenter certificate
function Ignore-Certificate {

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

}


#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Get-vCSA-Services {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )
       if (([regex]::match($vCSAVersion,"6.7")).success){
                  $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
                       $method = "GET"
            
                       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services
                       $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='Description';E={$_.value.description}},@{N='State';E={$_.value.state}} | Sort-Object -Property 'State'
      } else{
           $listvCSAServices = "The appliance.services API is not included in vSphere 6.5 REST API. Available only in vSphere 6.7.`n"
           return $listvCSAServices
       }
  
       return $listvCSAServices
}

#Function to list the status of the services managed by vmware-vmon(VMware Service Lifecycle Manager) service.
function Get-vMon-Services{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"            
 
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/vmon/service
       $listVmonServices = $respond.value | Select-Object -Property @{N='Services';E={$_.key}},@{N='Startup Type';E={$_.value.startup_type}},@{N='State';E={$_.value.state}},@{N='Health';E={$_.value.health}} | Sort-Object -Property 'State'
        
       return $listVmonServices
}

#Function to get vCSA version
function Get-vCSA-Version {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
        
       $method = "GET"
     
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/version
       $listvCSAVersion = $respond.value | Select-Object -Property @{N='Product';E={$_.product}},@{N='Summary';E={$_.summary}},@{N='Type';E={$_.type}},@{N='Install Time';E={$_.install_time}},@{N='Build';E={$_.build}},@{N='Version';E={$_.version}},@{N='Release Date';E={$_.releasedate}}
   
       return $listvCSAVersion
}

#Function to terminate the session 
function Terminate-Session {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
            
       $method = "DELETE"
            
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/com/vmware/cis/session
       $terminateSession = $respond.value | Select-Object -Property @{N='ESXi Host Name';E={$_.name}},@{N='Connection State';E={$_.connection_state} } ,@{N='Power State';E={$_.power_state} }
   
       return $terminateSession
}



#Main Program
DO{
    Write-Host "Enter the FQDN or the IP address of the vCenter Server:" -ForegroundColor Yellow
    $vCenterFQDN = Read-Host 
    
    Ignore-Certificate
    $response = try { 
                        Invoke-WebRequest $vCenterFQDN
                        $RestApiUrl ='https://'+$vCenterFQDN+'/rest/'
                    } catch { 
                        $_.Exception.Response; 
                        Write-Host "FQDN is not correct or vCenter IP is not reachable. Please check and try again." -ForegroundColor Red 
                    }
   
 }While ($response.StatusCode -ne '200')


DO{
    Write-Host "Enter your credentials to authenticate against vSphere REST API...."   $RestApiUrl -ForegroundColor Yellow
    $username = Read-Host "Enter username"
    $password = Read-Host -assecurestring "Enter password"
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    $creds = Set-Credentials -username $username -password $password
    $correctToken = 1

    try{
        $AuthenticationToken = Create-Session
        if ($AuthenticationToken.Value){
            Write-Host "Authentication Token acquired successfully" -ForegroundColor Green
            Start-Sleep -Seconds 2
            $correctToken = 0
            $FuncAuthToken = $AuthenticationToken.Value
        }
        
    }
    catch{
        Write-Host "Wrong Username or Password" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }

  }While ($correctToken -eq 1)  

#Get the vCSA version in order to check if appliance.services API is present (Present only in vCSA 6.7)
$vcsaVersion = Get-vCSA-Version -AuthTokenValue $FuncAuthToken

#Main menu loop
DO
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
             '1' {
                cls
                        Write-Host "The list of all vCSA services is:`n"
                        $vcsaServices = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion ($vcsaVersion.version) | ft
                        echo $vcsaServices

            } '2' {
                cls
                        Write-Host "The list of services managed by vmware-vmon (VMware Service Lifecycle Manager) is:`n"
                        $vmonServices = Get-vMon-Services -AuthTokenValue $FuncAuthToken  | ft
                        echo $vmonServices

			} '3'  {
                cls
                        Write-Host "Information list about the connected VMware vCSA:`n"
                        $vcsaVersionSelection = Get-vCSA-Version -AuthTokenValue $FuncAuthToken | fl
                        echo $vcsaVersionSelection
                   
            } 'q' {
                 
                        $quit = Terminate-Session -AuthTokenValue $FuncAuthToken | ft                         
                        Write-Host "vSphere REST API session terminated successfully" -ForegroundColor Green
            }
     }
   Pause
}
until ($input -eq 'q')