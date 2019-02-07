function Create-SharePointServiceAccounts{

    Write-Host "Creating Wingtip service accounts in Active Directory"

    # import module with ActiveDirectory cmdlets
    Write-Host " - loading PowerShell module with Active Directory cmdlets"
    Import-Module ActiveDirectory
   
    $WingtipDomain = "DC=wingtip,DC=com"
    $ouWingtipServiceAccountsName = "SharePoint Service Accounts"
    $ouWingtipServiceAccountsPath = "OU={0},{1}" -f $ouWingtipServiceAccountsName, $WingtipDomain
    $ouWingtipServiceAccounts = Get-ADOrganizationalUnit -Filter { name -eq $ouWingtipServiceAccountsName}

    if($ouWingtipServiceAccounts -ne $null){
        Write-Host ("The Organization Unit {0} has already been created" -f $ouWingtipServiceAccountsName)
    }

    Write-Host (" - creating {0} Organization Unit" -f $ouWingtipServiceAccountsName)
    New-ADOrganizationalUnit -Name $ouWingtipServiceAccountsName -Path $WingtipDomain -ProtectedFromAccidentalDeletion $false 

    $UserPassword = ConvertTo-SecureString -AsPlainText "PasswdHH.MA2k!" -Force

    # Get domain DNS suffix
    $dnsroot = '@' + (Get-ADDomain).dnsroot


    # create farm service account 
    $UserName = "SP_Farm"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create install service account 
    $UserName = "SP_Install"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # temporarily add SP_Farm account to local Administrators group for farm configuration 
    # NOTE: SP_Farm should be removed from Administrators group after farm configuration is complete
    $user_farm = Get-ADUser -Filter "samAccountName -eq 'SP_Farm'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_farm

    $user_install = Get-ADUser -Filter "samAccountName -eq 'SP_Install'"
    Add-ADGroupMember -Identity "Administrators" -Members $user_install

    # create service app service account 
    $UserName = "SP_Services"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_services = Get-ADUser -Filter "samAccountName -eq 'SP_Services'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_services

    # create service app service account 
    $UserName = "SP_Claims"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_claims = Get-ADUser -Filter "samAccountName -eq 'SP_Claims'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_claims

    # create service app service account 
    $UserName = "SP_Secure"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_secure = Get-ADUser -Filter "samAccountName -eq 'SP_Secure'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_secure

    # create service app service account 
    $UserName = "SP_Unattened"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_unattended = Get-ADUser -Filter "samAccountName -eq 'SP_Unattened'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_unattended

    # create service app service account 
    $UserName = "SP_Visio"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_visio = Get-ADUser -Filter "samAccountName -eq 'SP_Visio'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_visio    

    # create service app service account 
    $UserName = "SP_Excel"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Services to Performance Log Users group so it can write to ULS logs
    $user_excel = Get-ADUser -Filter "samAccountName -eq 'SP_Excel'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_excel      

    # create web app service account 
    $UserName = "SP_PortalAppPool"
    Write-Host (" - adding User: {0}" -f $UserName)
    # add account to 'Performance Log Users' group in AD in order for ULS logging to work correctly
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Content to Performance Log Users group so it can write to ULS logs
    $user_portal = Get-ADUser -Filter "samAccountName -eq 'SP_PortalAppPool'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_portal

    # create User Profile web app service account 
    $UserName = "SP_ProfileAppPool"
    Write-Host (" - adding User: {0}" -f $UserName)
    # add account to 'Performance Log Users' group in AD in order for ULS logging to work correctly
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_UserProfile to Performance Log Users group so it can write to ULS logs
    $user_profile = Get-ADUser -Filter "samAccountName -eq 'SP_ProfileAppPool'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_profile

    # create Search web app service account 
    $UserName = "SP_Search"
    Write-Host (" - adding User: {0}" -f $UserName)
    # add account to 'Performance Log Users' group in AD in order for ULS logging to work correctly
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add SP_Search to Performance Log Users group so it can write to ULS logs
    $user_content = Get-ADUser -Filter "samAccountName -eq 'SP_Search'"
    Add-ADGroupMember -Identity "Performance Log Users" -Members $user_content

    # create user profile synchronization account 
    $UserName = "SP_UPSync"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create search crawler account 
    $UserName = "SP_Crawler"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    
    # create workflow manager service account 
    $UserName = "SP_Workflow"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create SP Super User account 
    $UserName = "SP_SuperUser"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create SP Super Reader account 
    $UserName = "SP_SuperReader"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create SP SharePoint SMTP 
    $UserName = "SharePointAdmin"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SharePoint Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

    # create SQL Admin account 
    $UserName = "SQL_Admin"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SQL Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)
    # add sql_admin account to local Administrators group
    #$user_sqladmin = Get-ADUser -Filter "samAccountName -eq 'SQL_Admin'"
    #Add-ADGroupMember -Identity "Administrators" -Members $user_sqladmin

    # create SQL Services account 
    $UserName = "SQL_Services"
    Write-Host (" - adding User: {0}" -f $UserName)
    New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -Description "SQL Service Account"  -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName ($userName + $dnsroot)

}
