function Create-SharePointServiceAccounts{

    Write-Host "Creating Wingtip service accounts in Active Directory"

    # import module with ActiveDirectory cmdlets
    Write-Host " - loading PowerShell module with Active Directory cmdlets"
    Import-Module ActiveDirectory
   
    $WingtipDomain = "DC=wingtip,DC=com"
    $ouWingtipServiceAccountsName = "Wingtip Service Accounts"
    $ouWingtipServiceAccountsPath = "OU={0},{1}" -f $ouWingtipServiceAccountsName, $WingtipDomain
    $ouWingtipServiceAccounts = Get-ADOrganizationalUnit -Filter { name -eq $ouWingtipServiceAccountsName}

    if($ouWingtipServiceAccounts -ne $null){
        Write-Host ("The Organization Unit {0} has already been created" -f $ouWingtipServiceAccountsName)
    }

    Write-Host (" - creating {0} Organization Unit" -f $ouWingtipServiceAccountsName)
    New-ADOrganizationalUnit -Name $ouWingtipServiceAccountsName -Path $WingtipDomain -ProtectedFromAccidentalDeletion $false 

    $UserPassword = ConvertTo-SecureString -AsPlainText "Password1" -Force

    # create farm service account 
    $UserName = "SP_Farm"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

    # temporarily add SP_Farm account to local Administrators group for farm configuration 
    # NOTE: SP_Farm should be removed from Administrators group after farm configuration is complete
    $user_farm = Get-ADUser -Filter "samAccountName -eq 'SP_Farm'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_farm


    # create service app service account 
    $UserName = "SP_Services"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_services = Get-ADUser -Filter "samAccountName -eq 'SP_Services'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_services


    # create web app service account 
    $UserName = "SP_Content"
    Write-Host (" - adding User: {0}" -f $UserName)
    # add account to 'Performance Log Users' group in AD in order for ULS logging to work correctly
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add SP_Content to Performance Log Users group so it can write to ULS logs
    $user_content = Get-ADUser -Filter "samAccountName -eq 'SP_Content'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_content


    # create user profile synchronization account 
    $UserName = "SP_UPS"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add sp_ups account to local Administrators and Domain Admins group
    $user_ups = Get-ADUser -Filter "samAccountName -eq 'SP_UPS'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_ups
    Add-ADGroupMember -Identity "Domain Admins" -Members $user_ups


    # create search crawler account 
    $UserName = "SP_Crawler"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add sp_crawler account to local Administrators group
    $user_crawler = Get-ADUser -Filter "samAccountName -eq 'SP_Crawler'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_crawler


    # create workflow manager service account 
    $UserName = "SP_Workflow"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add sp_workflow account to local Administrators group
    $user_workflow = Get-ADUser -Filter "samAccountName -eq 'SP_Workflow'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_workflow

    # create SP Super User account 
    $UserName = "SP_SuperUser"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

    # create SP Super Reader account 
    $UserName = "SP_SuperReader"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true


    # create SQL Admin account 
    $UserName = "SQL_Admin"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    # add sql_admin account to local Administrators group
    $user_sqladmin = Get-ADUser -Filter "samAccountName -eq 'SQL_Admin'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_sqladmin

    # create SQL Services account 
    $UserName = "SQL_Services"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

}

# create active directory accounts for SharePoint service accounts
Create-SharePointServiceAccounts
