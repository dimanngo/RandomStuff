#Managed Identity Deep Dive Script
#onboardtoazure.com

#Look at all the service principals
#region ServicePrincipals

#Connect
#Each API in graph has a certain permission scope required

# Prerequisite (MasOS)
# 1. Install PowerShell: If you don't have PowerShell installed on your macOS, you can download and install it from the official Microsoft PowerShell GitHub repository.
# 2. Install the Microsoft Graph PowerShell SDK: Open a terminal window and run the following command to install the Microsoft Graph PowerShell module:
Install-Module -Name Microsoft.Graph
# 3. Connect to Microsoft Graph: Once the module is installed, import the Microsoft Graph module by running the command:
Import-Module -Name Microsoft.Graph

#https://docs.microsoft.com/en-us/graph/permissions-reference
#Application.Read.All to read the service principals
Connect-MgGraph -Scopes "Application.Read.All"
#Switch to beta profile to light up features
Select-MgProfile -Name "beta"

#View my scope
Get-MgContext #note my TenantId
(Get-MgContext).Scopes

#Environments, i.e. various clouds
Get-MgEnvironment

#View a regular app registration and its service principal
Get-MgApplication -Filter  "DisplayName eq 'RBACTestAppReg'"
Get-MgServicePrincipal -Filter "DisplayName eq 'RBACTestAppReg'" |
    Format-Table DisplayName, Id, AppId, SignInAudience, AppOwnerOrganizationId

#Same for an enterprise application that is enabled in my tenant
Get-MgServicePrincipal -Filter "DisplayName eq 'Netflix' or DisplayName eq 'Microsoft Teams'" |
    Format-Table DisplayName, Id, AppId, SignInAudience, AppOwnerOrganizationId

#View all managed identities. Note the different types of resource
Get-MgServicePrincipal -Filter "ServicePrincipalType eq 'ManagedIdentity'" |
    Format-Table DisplayName, Id, AlternativeNames -AutoSize

#View service principals for our focus managed identities which is name of resource for SA or UA-MI name
$SPs = Get-MgServicePrincipal -Filter "DisplayName eq 'mi-savilltech1' or DisplayName eq 'DemoVM'"
$SPs | format-table DisplayName,ServicePrincipalType,ID, AppID -autosize
#Note there is NO application for this service principal, its just randomly generated
Get-MgApplication -ApplicationId $SPs[0].AppID
#Can look at the detail but remember, we actually don't care about this SP really, its fully managed!
$SPs[0] | format-list

#another way to view them but less efficient
#$SPs = Get-MgServicePrincipal -All
#$SPs | where {$_.DisplayName -eq "mi-savilltech1" -or $_.DisplayName -eq "DemoVM"}
#endregion

#Managed Identity Demo
#region Managed Identity Demo on DemoVM

#Using Az module
Connect-AzAccount -Identity #Connect as the managed identity
Get-AzContext #note the account

#The system assigned MI has read role on the VM object
$VMRG = "RG-DEMOVM"
$VMName = "DemoVM"
$vmInfo = Get-AzVM -ResourceGroupName $VMRG -Name $VMName
$spID = $vmInfo.Identity.PrincipalId
write-output "The managed identity for Azure resources service principal ID is $spID"

#Look at storage
$storcontext = New-AzStorageContext -StorageAccountName 'sascussavilltech' -UseConnectedAccount
Get-AzStorageBlobContent -Container 'images' -Blob 'OllieandEddieCerealEating.jpg' `
    -Destination "C:\temp\" -Context $storcontext

#Look at a secret
$secretText = Get-AzKeyVaultSecret -VaultName "SavillVaultRBAC" -Name "Secret1" -AsPlainText
Write-Output $secretText

#We can use the REST API as well getting a token from the IMDS then using it to get the secrets
#Remember for VMs we use the Instance MetaData Service (IMDS), other resources access other endpoints applicable to their type
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -Method GET -Headers @{Metadata="true"}
$content = $response.Content | ConvertFrom-Json
$Token = $content.access_token
(Invoke-WebRequest -Uri https://SavillVaultRBAC.vault.azure.net/secrets/Secret1?api-version=2016-10-01 -Method GET -Headers @{Authorization="Bearer $Token"}).content


#Lets try another secret
$secretText2 = Get-AzKeyVaultSecret -VaultName "SavillVaultRBAC" -Name "Secret2" -AsPlainText

#User assigned managed identity examine
#Install the managed service identity module as not part of Az default
Install-Module az.ManagedServiceIdentity -Scope allusers -Force

$resourceGroupName = "RG-SCUSA"
$userAssignedIdentityName = "mi-savilltech1"
#Note I gave the SA-MI reader on the object so it could get the information on the resource
$usmi = Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $userAssignedIdentityName
$usmi

#Connect as the user assigned managed identity instead of the default system assigned
Connect-AzAccount -Identity -AccountId $usmi.ClientId
Get-AzContext

#Lets try to access that secret again
$secretText2 = Get-AzKeyVaultSecret -VaultName "SavillVaultRBAC" -Name "Secret2" -AsPlainText
$secretText2

#Note can easily set with PowerShell, CLI etc
Get-AzVM -ResourceGroupName $RG -Name $VM | Update-AzVM -IdentityType UserAssigned -IdentityId $usmi.Id


#Same works with AZ CLI
az login --identity
az resource list -n DemoVM --query [*].identity.principalId --out tsv
#Look at the secret 1 (that the system assigned had data RBAC on)
az keyvault secret show --vault-name SavillVaultRBAC --name Secret1 --query value -o tsv

#endregion
