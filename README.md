# simple-querys-siem
Coleção de **consultas simples** para hunting em SIEM.

> Copie‑e‑cole o bloco abaixo no seu SIEM ou use como ponto de partida para criar regras mais completas.

```kql
error.message: "whoami" OR error.message: "curl"

event.action: "SuspiciousActivity"

event.action: "DLPRuleMatch"

message: "Bad Robot"

message: "backdoor: Mirai.Botnet"

"web_app2: Cross.Site.Scripting"

event.action: "CommandAndControl"

"curl" OR "wget" OR "netcat"

auditd.log.proctitle: "whoami" OR process.args: "whoami" OR process.executable: "whoami" OR process.command_line: "whoami" OR file.name: "whoami.exe"

RunAsInvoker

process.name: "runas.exe"

file.name: "runas.exe"

message: "applications3"

file.name : *bypass*

event.action: "Discovery"

message: "MRE Alerta"

