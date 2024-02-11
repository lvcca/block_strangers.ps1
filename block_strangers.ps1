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
    $all_active_connections = $null
    $all_tcp_connections = $null

    $sus_hosts = New-Object Collections.Generic.List[String]
    $all_active_connections = New-Object Collections.Generic.List[String]
    $all_tcp_connections = Get-NetTCPConnection
    $dns_servers = @('8.8.8.8')
    $found_hosts = New-Object Collections.Generic.List[PSCustomObject]

    foreach ($curr_entry in $(Get-Content "$env:USERPROFILE\Desktop\Sus_Hosts.txt" | Get-Unique))
    {
        $sus_hosts.add($curr_entry)
    }

    foreach ($connection in $all_tcp_connections)
    {
        if ($connection.RemoteAddress -notlike '127.0.0.1' -and $connection.RemoteAddress -notlike '0.0.0.0' -and $connection.RemoteAddress -notlike '*::*')
        {
            if (!$sus_hosts.Contains($connection.RemoteAddress))
            {
                if (!$all_active_connections.contains([String]$connection.RemoteAddress))
                {
                    $all_active_connections.add($connection.RemoteAddress)
                }
            }
        }
    }

    foreach($active_connection in $all_active_connections)
    {

        $job_list = New-Object Collections.Generic.List[String]
        $found_flag = $false
        
        foreach($server in $dns_servers)
        {           
            $job_list.Add($tmp)
                
            Try
            {
                $found_host = ""
                $found_host = Resolve-DnsName $active_connection -erroraction Stop -QuickTimeout -Server $server
                $found_flag = $true

                if($found_flag -eq $true)
                {
                    #Write-Host 'Found ' $active_connection ':' $found_host.NameHost ' with ' $server
                    
                    $found = [PSCustomObject]@{
                        Remote_IP = $active_connection 
                        Remote_Name = $found_host.NameHost
                        Found_DNS_Server = $server
                    }
                    
                    $found_hosts.add($found);
                    break
                }
            }
        
            Catch 
            {
                Write-Host 'Could not find ' $active_connection ' with ' $server
            }                              
        }
        if($found_flag -eq $false)
        {
            Write-Host 'Added [' $active_connection '] to suspicious hosts.'
            $sus_hosts.Add( $active_connection )
        }
    }
    
    Clear-Host
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

