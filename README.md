# Test-NsxTepConflict

Script PowerShell 7 que procura conflitos de IP de TEP entre **NSX Edge Nodes** e **Host Transport Nodes** e confere se os **IP Pools** que entregam esses IPs estão consistentes. Ele só lê (faz apenas GET na API), então um usuário com papel **Auditor** já basta.

## Uso

```powershell
# Coleta direto do NSX (pede a credencial se -Credential não for passado)
./Test-NsxTepConflict.ps1 -NsxManager nsx01.lab.local -SkipCertificateCheck

# Coleta, salva o JSON bruto e exporta CSVs (inventário, achados, pools)
./Test-NsxTepConflict.ps1 -NsxManager nsx01.lab.local -SaveRawPath ./coleta.json -ReportPath ./relatorio

# Reanalisa uma coleta salva, sem acessar o NSX
./Test-NsxTepConflict.ps1 -FromRawPath ./samples/coleta-exemplo.json
```

Código de saída: `0` OK · `1` alertas · `2` críticos (serve para agendar ou usar em pipeline).

## O que é validado

| Severidade | Verificação |
|---|---|
| CRITICO | Mesmo IP de TEP em mais de um nó/interface (Edge x Host, Host x Host, Edge x Edge) |
| CRITICO | TEP igual a IP de gerência de algum transport node, ou igual a um gateway |
| CRITICO | Ranges sobrepostos entre pools que estão em uso |
| CRITICO | IP estático/DHCP (ou de outro pool) dentro do range de um pool que **já** alocou esse IP |
| CRITICO | Pool em uso esgotado |
| ALERTA | IP estático dentro do range de um pool: conflito latente, o pool pode entregar esse IP a outro nó |
| ALERTA | TEP vindo do pool que não aparece nas alocações do pool |
| ALERTA | TEP fora dos ranges do próprio pool; pool referenciado que não existe |
| ALERTA | Gateway dentro do range de alocação; uso do pool ≥ `-PoolUsageWarnPercent` (padrão 85%) |
| INFO | IP alocado no pool sem nenhum TEP usando (órfão); nó sem TEP realizado |

## APIs usadas

- `GET /api/v1/transport-nodes`, com fallback para `/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes`
- `GET /api/v1/transport-nodes/state`, com fallback por nó em `/api/v1/transport-nodes/{id}/state`. É daqui que vêm os IPs realmente em uso
- `GET /api/v1/pools/ip-pools` e `/{id}/allocations`, com fallback para `/policy/api/v1/infra/ip-pools` (sem lista de alocações)

Só IPv4 entra nas verificações de range. IPv6 entra apenas na verificação de duplicidade.
