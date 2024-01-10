[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
#Meraki API KEY
$api_key = ""
$api_key = Read-Host "What is your favorite color"



#Base API URL
<#Example paths include
organization to view org id
organizations/<org_id>/networks to view networks
networks/<network_id>/snmp to view snmp locally
networks/<network_id>/grouppolicies to view grouppolicies locally
organization to view org id
#>

function Get-ApiPath {
    param(
        [string]$path
    )
        $MerakiUri = "https://api.meraki.com/api/v1/$path"
        return $MerakiUri
}

$header = @{
    "X-Cisco-Meraki-API-Key" = $api_key
    "Content-Type" = 'application/json'
    "Accept" = "application/json"
}

#Declare path for restmethod
$MerakiUri_OrgId = Get-ApiPath "organizations"

#Get first JSON response of API call including OrgID
$Response_Org = Invoke-RestMethod -Method GET -Uri $MerakiUri_OrgId -Headers $header -Verbose 

#Take ID (653913) from response and save it
$OrgId = $Response_Org  | Select-Object -ExpandProperty id


#Org accumilator
$MainCSV_org = New-Object -TypeName PSObject

###hashtable of available link options
$Links = @("admins"
    "loginSecurity"
    "saml/idps"
    "samlRoles"
    "snmp"
    "alerts/settings")


######The following are from ORGID and are saved in sperate CSVs to be saved together later via seperate script probably
###Privileged Identities Access
##Update local Meraki Device Passwords to comply with new Premier System Account password policy, Emergency account best practices 

##Parse this loop to get build variables and CSVs. I can do this because i am keeping the json return as it comes.
foreach ($Link in $Links) {
    $Response = Invoke-RestMethod -Method GET -Uri "https://api.meraki.com/api/v1/organizations/653913/$Link" -Headers $header -Verbose
    $MainCSV_org | Add-Member  -NotePropertyName $Link -NotePropertyValue $Response -Force
    $Link = $Link.replace("/"," ")
    $Response | Export-Csv "$Link.csv"
}
$MainCSV_org | ConvertTo-Json | Out-File Org.json




######Lets break things down into their individual networks now
##Get Networks from OrgID
$MerakiUri_Networks = Get-ApiPath "organizations/$OrgId/networks"
$Response_Networks = Invoke-RestMethod -Method GET -Uri $MerakiUri_Networks -Headers $header -Verbose 



###Secure monitoring of Meraki Devices_Network Level
##Declare the SNMP variable
$Networks_SNMP=@()
$Network_Accumilator = New-Object -TypeName PSObject
Foreach ($Current_Network in $Response_Networks) {
    $MerakiUri_Network_Id_snmp = Get-ApiPath "networks/$($Current_Network.id)/snmp"
    $Response_Network_SNMP = Invoke-RestMethod -Method GET -Uri $MerakiUri_Network_Id_snmp -Headers $header -Verbose
    #Response doesn't include identifier. This adds response to the id then puts it in csv
    $Network_Accumilator | Add-Member  -NotePropertyName name -NotePropertyValue $Current_Network.name -Force
    $Network_Accumilator | Add-Member  -NotePropertyName access -NotePropertyValue $Response_Network_SNMP.access -Force
    $Network_Accumilator | Add-Member  -NotePropertyName communityString -NotePropertyValue $Response_Network_SNMP.communityString -Force
    $Networks_SNMP += $Network_Accumilator  | Select-Object name, access, communityString
}
#This variable holds network name, snmpaccess, snmpcommunityString
$Networks_SNMP | Export-Csv SNMP_local.csv -NoTypeInformation



###Remove or Remediate DNA Spaces Integration locationScanning is early release.
##Declare the mqttBrokers variable
$Networks_mqttBrokers=@()
$Network_Accumilator = New-Object -TypeName PSObject
Foreach ($Current_Network in $Response_Networks) {
    #Two URLS to deal with here
    $MerakiUri_Network_Id_mqttBrokers = Get-ApiPath "networks/$($Current_Network.id)/mqttBrokers"
    $Response_Network_mqttBrokers = Invoke-RestMethod -Method GET -Uri $MerakiUri_Network_Id_mqttBrokers -Headers $header -Verbose
    #Response doesn't include identifier. This adds response to the id then puts it in csv
    $Network_Accumilator | Add-Member  -NotePropertyName name -NotePropertyValue $Current_Network.name -Force
    $Network_Accumilator  | Add-Member  -NotePropertyName mqttname -NotePropertyValue $Response_Network_mqttBrokers.name -Force
    $Network_Accumilator  | Add-Member  -NotePropertyName host -NotePropertyValue $Response_Network_mqttBrokers.host -Force
    $Networks_mqttBrokers += $Network_Accumilator  | Select-Object name, host, mqttname
}
#This variable holds network name, timezone, snmpaccess, snmpcommunityString
$Networks_mqttBrokers | Export-Csv mqttBrokers.csv -NoTypeInformation



###Remove or Remediate DNA Spaces Integration
##Declare the locationScanning variable
$Networks_alertssettings=@()
Foreach ($Current_Network in $Response_Networks) {
    $MerakiUri_Network_Id_alertssettings = Get-ApiPath "networks/$($Current_Network.id)/alerts/settings"
    $Response_Network_alertssettings = Invoke-RestMethod -Method GET -Uri $MerakiUri_Network_Id_alertssettings -Headers $header -Verbose
    $Network_Accumilator = New-Object -TypeName PSObject
    $Network_Accumilator | Add-Member  -NotePropertyName networkname -NotePropertyValue  $Current_Network.name -Force
    $Network_Accumilator | Add-Member  -NotePropertyName destination -NotePropertyValue $Response_Network_alertssettings.defaultDestinations.emails -Force
    $j=0
    Foreach($Current_alert in $Response_Network_alertssettings.alerts) {
        $Network_Accumilator | Add-Member  -NotePropertyName $Current_alert.type -NotePropertyValue $Current_alert.enabled -Force
        $j++
    }
    $Networks_alertssettings += $Network_Accumilator 
   }
$Networks_alertssettings | Export-Csv alertsettings.csv -NoTypeInformation



#Enable WPA3 transition mode where possible
#Configure Access Points to have redundant authentication servers
#Enable the RADIUS Monitoring feature to proactively identify authentication related connectivity issues and failover accordingly
$Networks_SSIDS=@()
Foreach ($Current_Network in $Response_Networks) {
    $MerakiUri_Network_Id_SSIDS = Get-ApiPath "networks/$($Current_Network.id)/wireless/ssids"
    $Response_Network_SSIDS = Invoke-RestMethod -Method GET -Uri $MerakiUri_Network_Id_SSIDS -Headers $header -Verbose

        Foreach ($SSID in $Response_Network_SSIDS) {
            if ($SSID.enabled -eq "True") {
                $Network_Accumilator = New-Object -TypeName PSObject
                $Network_Accumilator | Add-Member  -NotePropertyName networkname -NotePropertyValue  $Current_Network.name -Force
                $Network_Accumilator | Add-Member  -NotePropertyName SSID -NotePropertyValue $SSID.name -Force
                $Network_Accumilator | Add-Member  -NotePropertyName authmode -NotePropertyValue $SSID.authmode -Force
                $Network_Accumilator | Add-Member  -NotePropertyName encryptionMode -NotePropertyValue $SSID.encryptionMode -Force
                $Network_Accumilator | Add-Member  -NotePropertyName wpaEncryptionMode -NotePropertyValue $SSID.wpaEncryptionMode -Force

                $stringRadServ =""
                Foreach($radiusServer in $SSID.radiusServers ) {
                    $stringRadServ += $radiusServer.host
                    if ($radiusServer -ne $SSID.radiusServers[-1]) {
                        $stringRadServ += ","
                    }
                }

                $stringAccServ =""
                Foreach($radiusAccountingServer in $SSID.radiusAccountingServers) {
                    $stringAccServ += $radiusAccountingServer.host
                    if ($radiusAccountingServer -ne $SSID.radiusAccountingServers[-1]) {
                        $stringAccServ += ","
                    }
                }

                $walledGarden = ""
                Foreach($walledGardenIP  in $SSID.walledGardenRanges) {
                    $walledGarden += $walledGardenIP
                    if ($walledGardenIP -ne $SSID.walledGardenRanges[-1]) {
                        $walledGarden += ","
                    }
                }

                $Network_Accumilator | Add-Member  -NotePropertyName radiusServerhosts -NotePropertyValue $stringRadServ  -Force
                $Network_Accumilator | Add-Member  -NotePropertyName radiusAccountingServerhosts -NotePropertyValue $stringAccServ  -Force
                $Network_Accumilator | Add-Member  -NotePropertyName WalledGarden -NotePropertyValue $walledGarden -Force
                $Networks_SSIDS += $Network_Accumilator 
        }
    }
   # $Networks_SSIDS += $Network_Accumilator 
}
$Networks_SSIDS | Export-Csv SSIDS.csv -NoTypeInformation
$Response_Network_SSIDS | ConvertTo-Json -Depth 10 | Out-file fullSSID.json



#Apply consistent Group Policy access controls by Device Type across locations / networks
#Review ACL / access in Group Policies
#Standardize Group Policy ACLs across locations / networks
$Networks_grouppolicies=@()
Foreach ($Current_Network in $Response_Networks) {
    $MerakiUri_Network_Id_grouppolicies = Get-ApiPath "networks/$($Current_Network.id)/groupPolicies"
    $Response_Network_grouppolicies = Invoke-RestMethod -Method GET -Uri $MerakiUri_Network_Id_grouppolicies -Headers $header -Verbose

    Foreach($Current_GroupPolicy in $Response_Network_grouppolicies) {
        Foreach($l3FirewallRule in $Current_GroupPolicy.firewallAndTrafficShaping.l3FirewallRules ) {
            $Network_Accumilator =  New-Object -TypeName PSObject
            $Network_Accumilator | Add-Member  -NotePropertyName networkname -NotePropertyValue  $Current_Network.name -Force
            $Network_Accumilator | Add-Member  -NotePropertyName GroupPolicyName -NotePropertyValue $Current_GroupPolicy.name -Force
            $Network_Accumilator | Add-Member  -NotePropertyName bandwidthsetting -NotePropertyValue $Current_GroupPolicy.bandwidth.settings -Force
            $Network_Accumilator | Add-Member  -NotePropertyName l3FirewallRulecomment -NotePropertyValue $l3FirewallRule.comment-Force
            $Network_Accumilator | Add-Member  -NotePropertyName l3FirewallRulepolicy -NotePropertyValue $l3FirewallRule.policy-Force
            $Network_Accumilator | Add-Member  -NotePropertyName l3FirewallRuleprotocol -NotePropertyValue $l3FirewallRule.protocol -Force
            $Network_Accumilator | Add-Member  -NotePropertyName l3FirewallRuledestport -NotePropertyValue $l3FirewallRule.destport -Force
            $Network_Accumilator | Add-Member  -NotePropertyName l3FirewallRuledestCidr -NotePropertyValue $l3FirewallRule.destCidr -Force
            $Networks_grouppolicies += $Network_Accumilator 
        }
    }
}
$Networks_grouppolicies  | Export-Csv GroupPolicy.csv -NoTypeInformation
$Response_Network_grouppolicies | ConvertTo-Json -Depth 10 | Out-file fullGoupPolicy.json