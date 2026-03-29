# CVEs da MikroTik com PoC pública confirmada ou exploit divulgado

Baseado em pesquisa até 2026-03-28.

Legenda de status:

- `confirmed_code`: encontrei repositório, gist ou Exploit-DB com PoC/código público.

- `exploit_disclosed`: o advisory informa exploit público/divulgado, mas eu não confirmei um repositório PoC canônico.


## CVE-2025-10948
- Produto: RouterOS
- Versões afetadas: RouterOS 7; mitigado em 7.20.1/7.21beta2
- Resumo: Buffer overflow em libjson.so no endpoint /rest/ip/address/print do REST API.
- Status PoC: exploit_disclosed
- Link PoC / referência: https://github.com/advisories/GHSA-xfr2-wmjg-pmwj
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2025-10948
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-10948
- Observações: O advisory informa que o exploit foi divulgado publicamente; não confirmei repositório PoC canônico.

## CVE-2025-6563
- Produto: RouterOS
- Versões afetadas: Versões abaixo de 7.19.2
- Resumo: XSS refletido no hotspot/login via parâmetro dst com javascript: e login forçado por URL.
- Status PoC: confirmed_code
- Link PoC / referência: https://www.exploit-db.com/exploits/52366
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2025-6563
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-6563

## CVE-2024-54772
- Produto: RouterOS / WinBox
- Versões afetadas: Long-term 6.43.13–6.49.13; stable 6.43–7.17.2; corrigido em 6.49.18/7.18
- Resumo: Enumeração de usuários no WinBox por diferença no tamanho da resposta.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/deauther890/CVE-2024-54772
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2024-54772
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-54772
- Observações: Há também implementação em Rust em outro repositório.

## CVE-2023-30800
- Produto: RouterOS
- Versões afetadas: RouterOS 6; corrigido em 6.49.10; v7 não afetado
- Resumo: Heap corruption no web server/JSProxy causando crash e reinício da interface web.
- Status PoC: confirmed_code
- Link PoC / referência: https://gist.github.com/j-baines/fdd1e85482838c6299900c1e859071c2
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2023-30800
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-30800
- Observações: Há gist e também repositório de DoS multithread.

## CVE-2023-30799
- Produto: RouterOS
- Versões afetadas: Stable antes de 6.49.7; long-term até 6.48.6
- Resumo: Escalada de privilégio de admin para super-admin via Winbox/HTTP, com potencial de execução de código.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/MarginResearch/FOISted
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2023-30799
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-30799

## CVE-2022-45315
- Produto: RouterOS
- Versões afetadas: Antes da stable 7.6
- Resumo: Out-of-bounds read no processo SNMP; pode levar a execução de código via pacote malicioso.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2022-45315/README.md
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2022-45315
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-45315

## CVE-2022-45313
- Produto: RouterOS
- Versões afetadas: Antes da stable 7.5
- Resumo: Out-of-bounds read no processo hotspot; pode levar a execução de código via mensagem nova maliciosa.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2022-45313/README.md
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2022-45313
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-45313

## CVE-2020-5720
- Produto: WinBox
- Versões afetadas: Antes de 3.21
- Resumo: Path traversal local/MITM em WinBox para criar arquivos arbitrários.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/tenable/routeros/blob/master/poc/cve_2020_5720/winbox_drop_file.py
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2020-5720
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-5720
- Observações: PoC público da Tenable para escrita arbitrária de arquivo via WinBox.

## CVE-2019-3981
- Produto: RouterOS / WinBox
- Versões afetadas: WinBox 3.20 e anteriores
- Resumo: MITM pode fazer downgrade da autenticação e recuperar username + hash MD5 da senha.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/tenable/routeros/blob/master/poc/cve_2019_3981/winbox_server.py
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2019-3981
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-3981
- Observações: PoC público da Tenable para downgrade/MITM do WinBox.

## CVE-2019-3943
- Produto: RouterOS
- Versões afetadas: Stable <=6.43.12; long-term <=6.42.12; testing <=6.44beta75
- Resumo: Directory traversal autenticado via HTTP/Winbox para ler/gravar fora do sandbox.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/tenable/routeros/blob/master/poc/cve_2019_3943_dev_shell/README.md
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2019-3943
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-3943

## CVE-2019-3924
- Produto: RouterOS
- Versões afetadas: Antes de 6.43.12 stable / 6.42.12 long-term
- Resumo: Firewall/NAT bypass: o roteador executa network requests definidos pelo usuário para WAN e LAN.
- Status PoC: confirmed_code
- Link PoC / referência: https://www.exploit-db.com/exploits/46444
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2019-3924
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-3924

## CVE-2018-14847
- Produto: RouterOS / WinBox
- Versões afetadas: RouterOS até 6.42
- Resumo: Directory traversal no WinBox com leitura arbitrária de arquivos e escrita autenticada.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/tenable/routeros/blob/master/poc/cve_2018_14847/README.md
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2018-14847
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-14847
- Observações: Há várias implementações públicas, inclusive By the Way e WinboxPoC.

## CVE-2018-7445
- Produto: RouterOS
- Versões afetadas: Antes de 6.41.3 / 6.42rc27
- Resumo: Buffer overflow no SMB service antes da autenticação; RCE remoto.
- Status PoC: confirmed_code
- Link PoC / referência: https://www.exploit-db.com/exploits/44290
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2018-7445
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-7445

## CVE-2017-20149
- Produto: RouterOS
- Versões afetadas: Antes de stable 6.38.5 / long-term 6.37.5
- Resumo: Chimay-Red: memory corruption no web server; RCE remoto e não autenticado.
- Status PoC: confirmed_code
- Link PoC / referência: https://github.com/BigNerd95/Chimay-Red
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2017-20149
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-20149

## CVE-2008-6976
- Produto: RouterOS
- Versões afetadas: 3.x até 3.13 e 2.x até 2.9.51
- Resumo: SNMP set request permite modificar configurações de NMS.
- Status PoC: confirmed_code
- Link PoC / referência: https://www.exploit-db.com/exploits/6366
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2008-6976
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2008-6976
