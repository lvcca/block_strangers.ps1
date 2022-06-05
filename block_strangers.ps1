#Author:   Mason Palma
#File:     block_strangers.ps1
#Purpose:  This script dynamically creates firewall rules to block unknown traffic.
#          Lowering the number of network connections maximizes the available throughput
#          for user needs. 
#
#
#MUST BE RUN WITH ADMIN PRIVS

$global:stopwatch =  [system.diagnostics.stopwatch]::StartNew();
$global:stopwatch.Start();
$global:iter = 0;

function clear_firewall 
{

    $firewall = Get-NetFirewallRule 

    foreach($rule in $firewall)
    {
        if ($rule.DisplayName -like 'Latest Sus Host List (OUT) 1' -or $rule.DisplayName -like 'Latest Sus Host List (IN) 1' )
        {
            $null = Remove-NetFirewallRule $rule.instanceid
        }
    }
}

function do-block {
    $sus_hosts = $null
    $list = $null
    $a = $null

    $sus_hosts = New-Object Collections.Generic.List[String]
    $list = New-Object Collections.Generic.List[String]
    $a = Get-NetTCPConnection
    $dns_servers = @('8.8.4.4') #Specify Trusted DNS Servers
    $found_hosts = New-Object Collections.Generic.List[PSCustomObject]

    foreach ($asd in $(Get-Content "$env:USERPROFILE\Desktop\Sus_Hosts.txt" | Get-Unique))
    {
        $sus_hosts.add($asd)
    }

    foreach ($b in $a)
    {
        if ($b.RemoteAddress -notlike '127.0.0.1' -and $b.RemoteAddress -notlike '0.0.0.0' -and $b.RemoteAddress -notlike '*::*')
        {
            if (!$sus_hosts.Contains($b.RemoteAddress))
            {
                if (!$list.contains([String]$b.RemoteAddress))
                {
                    $list.add($b.RemoteAddress)
                }
            }
        }
    }

    foreach($l in $list)
    {

        $job_list = New-Object Collections.Generic.List[String]
        $found_flag = $false
        
        foreach($server in $dns_servers)
        {           
            $job_list.Add($tmp)
                
            Try
            {
                $found_host = ""
                $found_host = Resolve-DnsName $l -erroraction Stop -QuickTimeout -Server $server
                $found_flag = $true

                if($found_flag -eq $true)
                {
                    #Write-Host 'Found ' $l ':' $found_host.NameHost ' with ' $server
                    
                    $found = [PSCustomObject]@{
                        Remote_IP = $l
                        Remote_Name = $found_host.NameHost
                        Found_DNS_Server = $server
                    }
                    
                    $found_hosts.add($found);
                    break
                }
            }
        
            Catch 
            {
                Write-Host 'Could not find ' $l ' with ' $server
            }                              
        }
        if($found_flag -eq $false)
        {
            Write-Host 'Added [' $l '] to suspicious hosts.'
            $sus_hosts.Add($l)
        }
    }    
    cls
    Write-Host 'Found Hosts'
    $found_hosts | format-table -AutoSize
    Write-Host '***************************'
    Write-Host `n

    $firewall = Get-NetFirewallRule 
    
    foreach($rule in $firewall)
    {
        if ($iter -eq 0)
        {
            if ($rule.DisplayName -like 'Latest Sus Host List (OUT)_0' -or $rule.DisplayName -like 'Latest Sus Host List (IN)_0' )
            {
                $null = Remove-NetFirewallRule $rule.instanceid
            }
        }

        if ($iter -eq 1)
        {
            if ($rule.DisplayName -like 'Latest Sus Host List (OUT)_1' -or $rule.DisplayName -like 'Latest Sus Host List (IN)_1' )
            {
                $null = Remove-NetFirewallRule $rule.instanceid
            }
        }

    }

    $sus_hosts | Get-Unique | Sort-Object | Out-File -FilePath "$env:USERPROFILE\Desktop\Sus_Hosts.txt"
    
    if ($iter -eq 1)
    {
        $null = New-NetFirewallRule -DisplayName "Latest Sus Host List (OUT)_1" -Direction Outbound 
        $null = New-NetFirewallRule -DisplayName "Latest Sus Host List (IN)_1" -Direction Inbound
    }

    elseif ($iter -eq 0)
    {
        $null = New-NetFirewallRule -DisplayName "Latest Sus Host List (OUT)_0" -Direction Outbound 
        $null = New-NetFirewallRule -DisplayName "Latest Sus Host List (IN)_0" -Direction Inbound
    }
    
    Write-Host 'Firewall updated with [' $sus_hosts.Count '] hosts. '
    Write-Host 'Iteration check [' $iter ']'
    Write-Host 'Total time elapsed: [' $stopwatch.Elapsed.TotalMinutes '] minutes. '

    if ($iter -eq 0)
    {
        Set-NetFirewallRule -DisplayName "Latest Sus Host List (OUT)_0" -Enabled True -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $sus_hosts 
        Set-NetFirewallRule -DisplayName "Latest Sus Host List (IN)_0" -Enabled True -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $sus_hosts 
        Set-Variable -Name "iter" -value "1" -scope global 
    }

    elseif ($iter -eq 1)
    {
        Set-NetFirewallRule -DisplayName "Latest Sus Host List (OUT)_1" -Enabled True -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $sus_hosts 
        Set-NetFirewallRule -DisplayName "Latest Sus Host List (IN)_1" -Enabled True -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $sus_hosts 
        Set-Variable -Name "iter" -value "0" -scope global 
    }
}

while($stopwatch.Elapsed.TotalMinutes -lt 360)
    {
        do-block
    }
    $stopwatch.Stop()

