#Requires -Version 7.0
<#
.SYNOPSIS
    Valida conflitos de IP de TEP entre NSX Edge Nodes e Host Transport Nodes,
    e a consistência dos IP Pools que entregam esses IPs.

.DESCRIPTION
    Coleta (somente leitura, via REST API do NSX Manager):
      - Transport nodes (Edges e Hosts) e a forma de atribuição de IP de TEP
        (IP Pool, lista estática, DHCP).
      - Estado realizado de cada nó (IPs de TEP efetivamente em uso).
      - IP Pools (ranges, gateway, uso e alocações).

    Verificações:
      [CRITICO] Mesmo IP de TEP em mais de um nó/interface (Edge x Host, Host x Host, Edge x Edge).
      [CRITICO] IP de TEP igual ao IP de gerência de algum transport node.
      [CRITICO] IP de TEP igual ao gateway de um pool/TEP.
      [CRITICO] Ranges de pools em uso (por TNs) se sobrepõem.
      [CRITICO] IP fora do pool (estático/DHCP/outro pool) dentro do range de um pool que JÁ o alocou.
      [CRITICO] Pool em uso sem IPs livres.
      [ALERTA]  IP fora do pool dentro do range de um pool (o pool pode entregá-lo a outro nó).
      [ALERTA]  IP em uso por TEP do pool mas não registrado como alocado no pool.
      [ALERTA]  IP atribuído pelo pool mas fora dos ranges do pool.
      [ALERTA]  Pool referenciado por TN não encontrado.
      [ALERTA]  Gateway dentro do range de alocação do pool.
      [ALERTA]  Ranges sobrepostos em pools não usados / no mesmo pool.
      [ALERTA]  Uso do pool acima de -PoolUsageWarnPercent.
      [INFO]    IP alocado no pool sem TEP correspondente (órfão).
      [INFO]    Transport node sem TEP realizado.

    Código de saída: 0 = OK, 1 = alertas, 2 = críticos.

.EXAMPLE
    ./Test-NsxTepConflict.ps1 -NsxManager nsx01.lab.local -SkipCertificateCheck

.EXAMPLE
    ./Test-NsxTepConflict.ps1 -NsxManager nsx01.lab.local -Credential $cred -SaveRawPath ./coleta.json -ReportPath ./relatorio

.EXAMPLE
    # Reanalisa uma coleta salva, sem acessar o NSX
    ./Test-NsxTepConflict.ps1 -FromRawPath ./coleta.json
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Live', Position = 0)]
    [string]$NsxManager,

    [Parameter(ParameterSetName = 'Live')]
    [pscredential]$Credential,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$SkipCertificateCheck,

    # Salva os dados coletados (normalizados) em JSON para reanálise offline.
    [Parameter(ParameterSetName = 'Live')]
    [string]$SaveRawPath,

    # Analisa um JSON salvo com -SaveRawPath em vez de consultar o NSX.
    [Parameter(Mandatory, ParameterSetName = 'Offline')]
    [string]$FromRawPath,

    # Pasta onde exportar CSVs (inventário de TEPs, achados, pools).
    [string]$ReportPath,

    [ValidateRange(1, 100)]
    [int]$PoolUsageWarnPercent = 85,

    # Devolve o objeto de resultado no pipeline.
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers de IP --------------------------------------------------------

function Get-NormalizedIp([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $null }
    $addr = $null
    if ([System.Net.IPAddress]::TryParse($Ip.Split('/')[0].Trim(), [ref]$addr)) { return $addr.ToString() }
    return $null
}

function ConvertTo-IpNumber([string]$Ip) {
    $addr = $null
    if (-not $Ip -or -not [System.Net.IPAddress]::TryParse($Ip.Split('/')[0].Trim(), [ref]$addr)) { return $null }
    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null } # IPv6: sem aritmética de range
    $b = $addr.GetAddressBytes(); [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-IpNumber([uint32]$N) {
    $b = [BitConverter]::GetBytes($N); [Array]::Reverse($b)
    return [System.Net.IPAddress]::new($b).ToString()
}

#endregion

#region REST -----------------------------------------------------------------

$script:Nsx = @{}

function Initialize-NsxSession([string]$Server, [pscredential]$Cred, [bool]$SkipCert) {
    $pair = '{0}:{1}' -f $Cred.UserName, $Cred.GetNetworkCredential().Password
    $script:Nsx.BaseUri  = "https://$Server"
    $script:Nsx.Headers  = @{
        Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
        Accept        = 'application/json'
    }
    $script:Nsx.SkipCert = $SkipCert
}

function Invoke-NsxGet([string]$Path) {
    Write-Verbose "GET $Path"
    Invoke-RestMethod -Uri ($script:Nsx.BaseUri + $Path) -Method Get -Headers $script:Nsx.Headers `
        -SkipCertificateCheck:$script:Nsx.SkipCert -ErrorAction Stop
}

# GET com paginação por cursor; devolve todos os itens de .results
function Get-NsxAll([string]$Path) {
    $cursor = $null
    do {
        $uri = $Path
        if ($cursor) { $uri += ($Path.Contains('?') ? '&' : '?') + 'cursor=' + [uri]::EscapeDataString($cursor) }
        $resp = Invoke-NsxGet $uri
        foreach ($r in @($resp.results)) { if ($null -ne $r) { $r } }
        $cursor = $resp.cursor
    } while ($cursor)
}

#endregion

#region Coleta ---------------------------------------------------------------

function ConvertTo-TnModel($Tn, [string]$Id, [string]$DefaultType = 'Desconhecido') {
    $ndi = $Tn.node_deployment_info
    $type = switch ($ndi.resource_type) {
        'EdgeNode'               { 'Edge' }
        'PublicCloudGatewayNode' { 'Edge' }
        'HostNode'               { 'Host' }
        default                  { $ndi.resource_type ?? $DefaultType }
    }

    $switches = foreach ($hs in @($Tn.host_switch_spec.host_switches)) {
        if (-not $hs) { continue }
        # NSX 4.x usa ip_assignment_specs (lista); versões anteriores ip_assignment_spec
        $specs = @($hs.ip_assignment_specs | Where-Object { $_ })
        if (-not $specs) { $specs = @($hs.ip_assignment_spec | Where-Object { $_ }) }
        if (-not $specs) {
            [pscustomobject]@{ HostSwitch = $hs.host_switch_name; Assignment = 'Nenhuma'; PoolId = $null; StaticIps = @(); Gateway = $null }
            continue
        }
        foreach ($s in $specs) {
            $static = switch ($s.resource_type) {
                'StaticIpListSpec'    { @($s.ip_list) }
                'StaticIpMacListSpec' { @($s.ip_mac_list | ForEach-Object { $_.ip }) }
                default               { @() }
            }
            [pscustomobject]@{
                HostSwitch = $hs.host_switch_name
                Assignment = $s.resource_type
                PoolId     = $s.ip_pool_id
                StaticIps  = @($static | Where-Object { $_ })
                Gateway    = $s.default_gateway
            }
        }
    }

    [pscustomobject]@{
        Id           = $Id
        Name         = $Tn.display_name
        Type         = $type
        MgmtIps      = @($ndi.ip_addresses | Where-Object { $_ })
        State        = $null
        HostSwitches = @($switches)
        Endpoints    = @()
    }
}

function Set-TnState($Node, $State) {
    $Node.State = $State.state ?? $State.node_deployment_state.state
    $Node.Endpoints = @(
        foreach ($hss in @($State.host_switch_states)) {
            foreach ($ep in @($hss.endpoints)) {
                if (-not $ep -or -not $ep.ip) { continue }
                [pscustomobject]@{
                    HostSwitch = $hss.host_switch_name
                    Device     = $ep.device_name
                    Ip         = $ep.ip
                    SubnetMask = $ep.subnet_mask
                    Gateway    = $ep.default_gateway
                }
            }
        }
    )
}

function ConvertTo-PoolSubnet($S) {
    [pscustomobject]@{
        Cidr    = $S.cidr
        Gateway = $S.gateway_ip
        Ranges  = @(foreach ($r in @($S.allocation_ranges)) { if ($r) { [pscustomobject]@{ Start = $r.start; End = $r.end } } })
    }
}

function Get-NsxTepPools {
    $pools = [System.Collections.Generic.List[object]]::new()
    $mgrOk = $false

    # Manager API: tem as alocações reais (inclusive as feitas para TEPs)
    try {
        $mgrPools = @(Get-NsxAll '/api/v1/pools/ip-pools')
        $mgrOk = $true
        foreach ($p in $mgrPools) {
            $allocs = @(); $allocOk = $false
            try {
                $allocs = @(Get-NsxAll "/api/v1/pools/ip-pools/$($p.id)/allocations" | ForEach-Object { $_.allocation_id } | Where-Object { $_ })
                $allocOk = $true
            } catch { Write-Warning "Não foi possível ler alocações do pool '$($p.display_name)': $($_.Exception.Message)" }
            $u = $p.pool_usage
            $pools.Add([pscustomobject]@{
                Id                   = $p.id
                Name                 = $p.display_name
                AltIds               = @($p.id)
                Source               = 'Manager API'
                Subnets              = @(foreach ($s in @($p.subnets)) { if ($s) { ConvertTo-PoolSubnet $s } })
                Allocations          = $allocs
                AllocationsAvailable = $allocOk
                Usage                = $u ? [pscustomobject]@{ Total = $u.total_ids; Allocated = $u.allocated_ids; Free = $u.free_ids } : $null
            })
        }
    } catch {
        Write-Warning "Manager API de IP pools indisponível ($($_.Exception.Message)). Usando Policy API (sem lista de alocações)."
    }

    # Policy API: usado para mapear path/IDs de policy -> pool, ou como fallback completo
    $polPools = @()
    try { $polPools = @(Get-NsxAll '/policy/api/v1/infra/ip-pools') }
    catch { if (-not $mgrOk) { throw "Não foi possível ler IP pools nem pela Manager nem pela Policy API: $($_.Exception.Message)" } }

    foreach ($p in $polPools) {
        $polIds = @($p.id, $p.path, $p.unique_id, $p.realization_id) | Where-Object { $_ }
        if ($mgrOk) {
            $match = $pools | Where-Object { $_.Id -in $polIds } | Select-Object -First 1
            $match ??= $pools | Where-Object Name -eq $p.display_name | Select-Object -First 1
            if ($match) { $match.AltIds = @(@($match.AltIds) + $polIds | Select-Object -Unique) }
        } else {
            $subnets = @(Get-NsxAll "/policy/api/v1/infra/ip-pools/$([uri]::EscapeDataString($p.id))/ip-subnets" |
                Where-Object { $_.allocation_ranges } | ForEach-Object { ConvertTo-PoolSubnet $_ })
            $u = $p.pool_usage
            $pools.Add([pscustomobject]@{
                Id                   = $p.id
                Name                 = $p.display_name
                AltIds               = @($polIds)
                Source               = 'Policy API'
                Subnets              = $subnets
                Allocations          = @()
                AllocationsAvailable = $false
                Usage                = $u ? [pscustomobject]@{ Total = $u.total_ids; Allocated = $u.allocated_ids; Free = $u.available_ids ?? $u.free_ids } : $null
            })
        }
    }
    return $pools.ToArray()
}

function Get-NsxTepData {
    Write-Host '[1/3] Coletando transport nodes...' -ForegroundColor Cyan
    $nodes = [System.Collections.Generic.List[object]]::new()
    foreach ($tn in Get-NsxAll '/api/v1/transport-nodes') {
        $nodes.Add((ConvertTo-TnModel $tn $tn.id))
    }
    # NSX 4.x: hosts podem não aparecer na Manager API -> Policy API
    if (-not ($nodes | Where-Object Type -eq 'Host')) {
        try {
            foreach ($tn in Get-NsxAll '/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes') {
                $id = $tn.unique_id ?? $tn.id
                if (-not ($nodes | Where-Object Id -eq $id)) { $nodes.Add((ConvertTo-TnModel $tn $id 'Host')) }
            }
        } catch { Write-Warning "Não foi possível listar host transport nodes via Policy API: $($_.Exception.Message)" }
    }
    Write-Host ("      {0} edges, {1} hosts" -f @($nodes | Where-Object Type -eq 'Edge').Count, @($nodes | Where-Object Type -eq 'Host').Count)

    Write-Host '[2/3] Coletando estado realizado (IPs de TEP em uso)...' -ForegroundColor Cyan
    $stateMap = @{}
    try { foreach ($s in Get-NsxAll '/api/v1/transport-nodes/state') { if ($s.transport_node_id) { $stateMap[$s.transport_node_id] = $s } } }
    catch { Write-Verbose "Listagem em lote de estados falhou, consultando nó a nó: $($_.Exception.Message)" }

    $i = 0
    foreach ($n in $nodes) {
        $i++
        Write-Progress -Activity 'Estado dos transport nodes' -Status $n.Name -PercentComplete (100 * $i / $nodes.Count)
        $s = $stateMap[$n.Id]
        if (-not $s) {
            try { $s = Invoke-NsxGet "/api/v1/transport-nodes/$($n.Id)/state" }
            catch { Write-Warning "Falha ao obter estado de '$($n.Name)': $($_.Exception.Message)" }
        }
        if ($s) { Set-TnState $n $s }
    }
    Write-Progress -Activity 'Estado dos transport nodes' -Completed

    Write-Host '[3/3] Coletando IP pools...' -ForegroundColor Cyan
    $pools = Get-NsxTepPools

    [pscustomobject]@{
        SchemaVersion  = 1
        CollectedAt    = (Get-Date).ToString('s')
        Source         = $NsxManager
        TransportNodes = $nodes.ToArray()
        Pools          = $pools
    }
}

#endregion

#region Análise --------------------------------------------------------------

function Invoke-TepAnalysis($Data) {
    $findings = [System.Collections.Generic.List[object]]::new()
    function Add-Finding($Severity, $Check, $Ip, $Object, $Detail) {
        $findings.Add([pscustomobject][ordered]@{ Severidade = $Severity; Verificacao = $Check; IP = $Ip; Objeto = $Object; Detalhe = $Detail })
    }

    $nodes = @($Data.TransportNodes | Where-Object { $_ })

    # --- Modelo dos pools
    $pools = @(foreach ($p in @($Data.Pools | Where-Object { $_ })) {
        $ranges = @(foreach ($s in @($p.Subnets | Where-Object { $_ })) {
            foreach ($r in @($s.Ranges | Where-Object { $_ })) {
                $a = ConvertTo-IpNumber $r.Start; $b = ConvertTo-IpNumber $r.End
                if ($null -eq $a -or $null -eq $b) { continue }
                [pscustomobject]@{ Start = $r.Start; End = $r.End; StartN = [Math]::Min($a, $b); EndN = [Math]::Max($a, $b); Cidr = $s.Cidr }
            }
        })
        $allocSet = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ip in @($p.Allocations)) { $n = Get-NormalizedIp $ip; if ($n) { [void]$allocSet.Add($n) } }
        [pscustomobject]@{
            Id                   = $p.Id
            Name                 = $p.Name
            Keys                 = @($p.AltIds | Where-Object { $_ })
            Ranges               = $ranges
            Gateways             = @($p.Subnets | Where-Object { $_.Gateway } | ForEach-Object { Get-NormalizedIp $_.Gateway } | Where-Object { $_ })
            Allocations          = $allocSet
            AllocationsAvailable = [bool]$p.AllocationsAvailable
            Usage                = $p.Usage
            UsedBy               = [System.Collections.Generic.List[string]]::new()
        }
    })

    function Find-Pool([string]$Ref) {
        if (-not $Ref) { return $null }
        $hit = $pools | Where-Object { $Ref -in $_.Keys } | Select-Object -First 1
        if (-not $hit) { $leaf = ($Ref -split '/')[-1]; $hit = $pools | Where-Object { $leaf -in $_.Keys } | Select-Object -First 1 }
        return $hit
    }
    function Test-InPool($IpN, $Pool) {
        if ($null -eq $IpN -or -not $Pool) { return $false }
        foreach ($r in $Pool.Ranges) { if ($IpN -ge $r.StartN -and $IpN -le $r.EndN) { return $true } }
        return $false
    }

    # --- Inventário de TEPs (realizados + estáticos configurados ainda não realizados)
    $inv = [System.Collections.Generic.List[object]]::new()
    foreach ($n in $nodes) {
        $switches = @($n.HostSwitches | Where-Object { $_ })
        foreach ($sw in $switches | Where-Object PoolId) {
            $pool = Find-Pool $sw.PoolId
            if ($pool) { $pool.UsedBy.Add("$($n.Type):$($n.Name)") }
            else { Add-Finding 'ALERTA' 'Pool referenciado não encontrado' '' "$($n.Type) $($n.Name) [$($sw.HostSwitch)]" "ip_pool_id '$($sw.PoolId)' não corresponde a nenhum pool coletado." }
        }

        $newEntry = {
            param($Ip, $HostSwitch, $Device, $Sw, $Source)
            $pool = if ($Sw -and $Sw.PoolId) { Find-Pool $Sw.PoolId } else { $null }
            [pscustomobject][ordered]@{
                IP         = $Ip
                No         = $n.Name
                Tipo       = $n.Type
                HostSwitch = $HostSwitch
                Interface  = $Device
                Atribuicao = $Sw ? $Sw.Assignment : 'Desconhecida'
                Pool       = $pool ? $pool.Name : ($Sw.PoolId ?? '')
                Origem     = $Source
                Estado     = $n.State
                NodeId     = $n.Id
                IpN        = ConvertTo-IpNumber $Ip
                PoolObj    = $pool
            }
        }

        $seen = @{}
        foreach ($ep in @($n.Endpoints | Where-Object { $_ })) {
            $ip = Get-NormalizedIp $ep.Ip; if (-not $ip) { continue }
            $sw = $switches | Where-Object HostSwitch -eq $ep.HostSwitch | Select-Object -First 1
            if (-not $sw -and $switches.Count -eq 1) { $sw = $switches[0] }
            $inv.Add((& $newEntry $ip $ep.HostSwitch $ep.Device $sw 'Realizado'))
            $seen[$ip] = $true
        }
        foreach ($sw in $switches) {
            foreach ($sip in @($sw.StaticIps)) {
                $ip = Get-NormalizedIp $sip
                if ($ip -and -not $seen[$ip]) { $inv.Add((& $newEntry $ip $sw.HostSwitch '' $sw 'Configurado (não realizado)')); $seen[$ip] = $true }
            }
        }
        if (-not $seen.Count -and $switches.Count) {
            Add-Finding 'INFO' 'Transport node sem TEP realizado' '' "$($n.Type) $($n.Name)" "Estado: $($n.State ?? 'desconhecido'). IPs deste nó não puderam ser validados."
        }
    }
    $invIps = [System.Collections.Generic.HashSet[string]]::new([string[]]@($inv.IP))

    # --- 1. IP duplicado entre nós/interfaces
    foreach ($g in $inv | Group-Object IP) {
        $owners = @($g.Group | Group-Object { "$($_.NodeId)|$($_.Interface)" })
        if ($owners.Count -lt 2) { continue }
        $types = @($g.Group.Tipo | Sort-Object -Unique)
        $cat = $types.Count -eq 1 ? "$($types[0]) x $($types[0])" : ($types -join ' x ')
        $who = ($g.Group | ForEach-Object { "$($_.Tipo) $($_.No) [$($_.Interface)$(if ($_.Origem -ne 'Realizado') { ', não realizado' })]" }) -join '; '
        Add-Finding 'CRITICO' "IP de TEP duplicado ($cat)" $g.Name $who 'O mesmo IP de TEP está em mais de um nó/interface.'
    }

    # --- 2. TEP = IP de gerência
    $mgmt = @{}
    foreach ($n in $nodes) { foreach ($m in @($n.MgmtIps)) { $k = Get-NormalizedIp $m; if ($k) { $mgmt[$k] = @($mgmt[$k]) + "$($n.Type) $($n.Name)" | Where-Object { $_ } } } }
    foreach ($e in $inv) {
        if ($mgmt.ContainsKey($e.IP)) {
            Add-Finding 'CRITICO' 'TEP igual a IP de gerência' $e.IP "$($e.Tipo) $($e.No) [$($e.Interface)]" "IP de gerência de: $($mgmt[$e.IP] -join ', ')"
        }
    }

    # --- 3. TEP = gateway
    $gateways = @{}
    foreach ($p in $pools) { foreach ($gw in $p.Gateways) { $gateways[$gw] = "pool $($p.Name)" } }
    foreach ($n in $nodes) {
        foreach ($gw in @($n.Endpoints.Gateway) + @($n.HostSwitches.Gateway)) { $k = Get-NormalizedIp $gw; if ($k -and -not $gateways[$k]) { $gateways[$k] = "TEPs de $($n.Name)" } }
    }
    foreach ($e in $inv) {
        if ($gateways.ContainsKey($e.IP)) { Add-Finding 'CRITICO' 'TEP igual a gateway' $e.IP "$($e.Tipo) $($e.No) [$($e.Interface)]" "Gateway de $($gateways[$e.IP])." }
    }

    # --- 4/5. Consistência TEP x pool
    foreach ($e in $inv) {
        $obj = "$($e.Tipo) $($e.No) [$($e.Interface)]"
        if ($e.PoolObj -and $null -ne $e.IpN -and -not (Test-InPool $e.IpN $e.PoolObj)) {
            Add-Finding 'ALERTA' 'IP fora do range do próprio pool' $e.IP $obj "Atribuído pelo pool '$($e.PoolObj.Name)', mas fora dos ranges dele (ranges alterados após a alocação?)."
        }
        if ($e.PoolObj -and $e.Origem -eq 'Realizado' -and $e.PoolObj.AllocationsAvailable -and -not $e.PoolObj.Allocations.Contains($e.IP)) {
            Add-Finding 'ALERTA' 'TEP não registrado como alocado no pool' $e.IP $obj "O pool '$($e.PoolObj.Name)' não lista este IP como alocado e pode entregá-lo a outro nó."
        }
        # IP dentro do range de um pool que não é o que o atribuiu
        foreach ($p in $pools) {
            if ($p -eq $e.PoolObj -or -not (Test-InPool $e.IpN $p)) { continue }
            $how = $e.PoolObj ? "vem do pool '$($e.PoolObj.Name)'" : "atribuição $($e.Atribuicao)"
            if ($p.AllocationsAvailable -and $p.Allocations.Contains($e.IP)) {
                Add-Finding 'CRITICO' 'IP fora do pool já alocado pelo pool' $e.IP $obj "IP ($how) está no range do pool '$($p.Name)', que JÁ o alocou para outro consumidor."
            } else {
                Add-Finding 'ALERTA' 'IP fora do pool dentro do range de um pool' $e.IP $obj "IP ($how) está no range do pool '$($p.Name)'; o pool pode entregá-lo a outro nó (conflito latente)."
            }
        }
    }

    # --- 6. Sobreposição de ranges
    for ($i = 0; $i -lt $pools.Count; $i++) {
        $pi = $pools[$i]
        for ($a = 0; $a -lt $pi.Ranges.Count; $a++) {
            for ($b = $a + 1; $b -lt $pi.Ranges.Count; $b++) {
                $r1 = $pi.Ranges[$a]; $r2 = $pi.Ranges[$b]
                if ($r1.StartN -le $r2.EndN -and $r2.StartN -le $r1.EndN) {
                    Add-Finding 'ALERTA' 'Ranges sobrepostos no mesmo pool' '' "pool $($pi.Name)" "$($r1.Start)-$($r1.End) x $($r2.Start)-$($r2.End)"
                }
            }
        }
        for ($j = $i + 1; $j -lt $pools.Count; $j++) {
            $pj = $pools[$j]
            # Só interessa sobreposição envolvendo pelo menos um pool de TEP (usado por TN);
            # pools internos (169.254.x, VPC, SI etc.) se sobrepõem por design.
            if (-not $pi.UsedBy.Count -and -not $pj.UsedBy.Count) { continue }
            foreach ($r1 in $pi.Ranges) {
                foreach ($r2 in $pj.Ranges) {
                    if (-not ($r1.StartN -le $r2.EndN -and $r2.StartN -le $r1.EndN)) { continue }
                    $ov = '{0}-{1}' -f (ConvertFrom-IpNumber ([Math]::Max($r1.StartN, $r2.StartN))), (ConvertFrom-IpNumber ([Math]::Min($r1.EndN, $r2.EndN)))
                    $bothUsed = $pi.UsedBy.Count -gt 0 -and $pj.UsedBy.Count -gt 0
                    Add-Finding ($bothUsed ? 'CRITICO' : 'ALERTA') 'Ranges sobrepostos entre pools' $ov "pools $($pi.Name) x $($pj.Name)" `
                        ("$($pi.Name) $($r1.Start)-$($r1.End) x $($pj.Name) $($r2.Start)-$($r2.End)" + ($bothUsed ? ' — ambos em uso por transport nodes.' : ''))
                }
            }
        }
    }

    # --- 7. Gateway dentro do range, alocações órfãs, uso
    $poolSummary = foreach ($p in $pools) {
        if ($p.UsedBy.Count -and -not $p.Gateways.Count) {
            Add-Finding 'ALERTA' 'Pool de TEP sem gateway' '' "pool $($p.Name)" `
                "Os TEPs de $($p.UsedBy.Count) nó(s) ($(($p.UsedBy | ForEach-Object { ($_ -split ':', 2)[1] }) -join ', ')) ficam sem default gateway: só alcançam TEPs no mesmo segmento L2."
        }
        foreach ($gw in $p.Gateways) {
            if (Test-InPool (ConvertTo-IpNumber $gw) $p) { Add-Finding 'ALERTA' 'Gateway dentro do range de alocação' $gw "pool $($p.Name)" 'O pool pode entregar o IP do gateway a um TEP.' }
        }
        if ($p.AllocationsAvailable -and $p.UsedBy.Count) {
            foreach ($ip in $p.Allocations) {
                if (-not $invIps.Contains($ip)) { Add-Finding 'INFO' 'Alocação sem TEP correspondente' $ip "pool $($p.Name)" 'Alocado no pool, mas nenhum TEP coletado usa este IP (outro consumidor ou resto de nó removido?).' }
            }
        }

        $total = [long]($p.Usage.Total ?? 0)
        if ($total -le 0) { $total = ($p.Ranges | ForEach-Object { [long]$_.EndN - $_.StartN + 1 } | Measure-Object -Sum).Sum ?? 0 }
        $alloc = [long]($p.Usage.Allocated ?? $p.Allocations.Count)
        $pct = $total ? [Math]::Round(100.0 * $alloc / $total, 1) : 0
        if ($p.UsedBy.Count -and $total) {
            if ($alloc -ge $total) { Add-Finding 'CRITICO' 'Pool esgotado' '' "pool $($p.Name)" "$alloc/$total IPs alocados." }
            elseif ($pct -ge $PoolUsageWarnPercent) { Add-Finding 'ALERTA' 'Pool com uso alto' '' "pool $($p.Name)" "$alloc/$total ($pct%) alocados." }
        }

        [pscustomobject][ordered]@{
            Pool       = $p.Name
            Ranges     = ($p.Ranges | ForEach-Object { "$($_.Start)-$($_.End)" }) -join ', '
            Gateway    = $p.Gateways -join ', '
            Uso        = $total ? "$alloc/$total ($pct%)" : 'n/d'
            Edges      = @($p.UsedBy | Where-Object { $_ -like 'Edge:*' }).Count
            Hosts      = @($p.UsedBy | Where-Object { $_ -like 'Host:*' }).Count
            Alocacoes  = $p.AllocationsAvailable ? 'sim' : 'não disponível'
        }
    }

    $order = @{ CRITICO = 0; ALERTA = 1; INFO = 2 }
    [pscustomobject]@{
        Inventory = @($inv | Select-Object IP, No, Tipo, HostSwitch, Interface, Atribuicao, Pool, Origem, Estado | Sort-Object { ConvertTo-IpNumber $_.IP }, No)
        Pools     = @($poolSummary)
        Findings  = @($findings | Sort-Object { $order[$_.Severidade] }, Verificacao, { ConvertTo-IpNumber $_.IP })
        Nodes     = $nodes
    }
}

#endregion

#region Main -----------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Offline') {
    $data = Get-Content -Raw -LiteralPath $FromRawPath | ConvertFrom-Json
    Write-Host "Analisando coleta offline de '$($data.Source)' ($($data.CollectedAt))" -ForegroundColor Cyan
} else {
    $Credential ??= Get-Credential -Message "Credencial do NSX Manager $NsxManager (somente leitura basta)"
    Initialize-NsxSession $NsxManager $Credential $SkipCertificateCheck.IsPresent
    $data = Get-NsxTepData
    if ($SaveRawPath) {
        $data | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $SaveRawPath -Encoding utf8
        Write-Host "Coleta salva em $SaveRawPath"
    }
}

$result = Invoke-TepAnalysis $data

$edges = @($result.Nodes | Where-Object Type -eq 'Edge').Count
$hosts = @($result.Nodes | Where-Object Type -eq 'Host').Count
Write-Host ''
Write-Host "=== Resumo: $edges edges, $hosts hosts, $($result.Inventory.Count) IPs de TEP, $($result.Pools.Count) pools ===" -ForegroundColor Cyan

$tepPools = @($result.Pools | Where-Object { $_.Edges + $_.Hosts -gt 0 })
Write-Host "`nIP Pools de TEP (usados por transport nodes):" -ForegroundColor Cyan
$tepPools | Format-Table -AutoSize -Wrap | Out-Host
if ($result.Pools.Count -gt $tepPools.Count) {
    Write-Host "($($result.Pools.Count - $tepPools.Count) outros pools não são usados por TEP; entram só na checagem de IP de TEP dentro de range. Lista completa no CSV.)`n" -ForegroundColor DarkGray
}
Write-Host 'TEPs:' -ForegroundColor Cyan
$result.Inventory | Format-Table IP, No, Tipo, Interface, Atribuicao, Pool, Origem -AutoSize | Out-Host

$crit = @($result.Findings | Where-Object Severidade -eq 'CRITICO').Count
$warn = @($result.Findings | Where-Object Severidade -eq 'ALERTA').Count
$info = @($result.Findings | Where-Object Severidade -eq 'INFO').Count

if ($result.Findings.Count) {
    Write-Host 'Achados:' -ForegroundColor Cyan
    $sevColor = @{ CRITICO = 'Red'; ALERTA = 'Yellow'; INFO = 'Gray' }
    foreach ($f in $result.Findings) {
        $ipTxt = $f.IP ? " $($f.IP)" : ''
        Write-Host ("[{0}] {1}{2} — {3}" -f $f.Severidade, $f.Verificacao, $ipTxt, $f.Objeto) -ForegroundColor $sevColor[$f.Severidade]
        Write-Host "    $($f.Detalhe)"
    }
    Write-Host ''
}

$color = $crit ? 'Red' : ($warn ? 'Yellow' : 'Green')
Write-Host ("Resultado: {0} crítico(s), {1} alerta(s), {2} info" -f $crit, $warn, $info) -ForegroundColor $color

if ($ReportPath) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $result.Inventory | Export-Csv (Join-Path $ReportPath "tep-inventario-$stamp.csv") -NoTypeInformation -UseCulture -Encoding utf8BOM
    $result.Findings  | Export-Csv (Join-Path $ReportPath "tep-achados-$stamp.csv")    -NoTypeInformation -UseCulture -Encoding utf8BOM
    $result.Pools     | Export-Csv (Join-Path $ReportPath "tep-pools-$stamp.csv")      -NoTypeInformation -UseCulture -Encoding utf8BOM
    Write-Host "Relatórios CSV gravados em $ReportPath"
}

if ($PassThru) { $result }

exit ($crit ? 2 : ($warn ? 1 : 0))

#endregion
