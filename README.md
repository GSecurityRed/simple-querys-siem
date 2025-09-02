# simple-querys-siem
Coleção de **consultas simples** para hunting em SIEM.

> Copie‑e‑cole o bloco abaixo no seu SIEM ou use como ponto de partida para criar regras mais completas.

```kql

event.code:15 -> (FileCreateStreamHash), que representa um evento de download de arquivo do navegador.

winlog.event_data.param20: "wget"

event.action: "Web Event"

error.message: "whoami" OR error.message: "curl"

event.action: "Execute a Remote Command"

winlog.event_data.TaskContent

rule.category: "Pornography"

"wmic.exe" and (*.command_line:create or *.command_line:node or *.command_line:processor or *.command_line:call )

event.action: "SuspiciousActivity"

event.action: "DLPRuleMatch"

message: "Bad Robot"

message: "backdoor: Mirai.Botnet"

"web_app2: Cross.Site.Scripting"

event.action: "CommandAndControl"

"curl" OR "wget" OR "netcat"   *curl* or *wget* or *netcat*

auditd.log.proctitle: "whoami" OR process.args: "whoami" OR process.executable: "whoami" OR process.command_line: "whoami" OR file.name: "whoami.exe"

RunAsInvoker

event.action: "Malware"

process.name: "runas.exe"

file.name: "runas.exe"

message: "applications3"

file.name : *bypass*

event.action : "scheduled-task-created"

powershell.file.script_block_text


event.action: "Discovery"

message: "MRE Alerta"

winlog.event_id: 4722 -> Indica que uma conta de usuário foi habilitada (ou “ativada”) no Active Directory ou no SAM local.

winlog.event_id: 4724 -> reset e senha de usuário 

winlog.event_id: 4723 -> Quando um usuário autenticado solicita a alteração da própria senha

winlog.event_id: 4738  -> Este evento é gerado sempre que qualquer atributo de uma conta de usuário é alterado (exceto senha).

(process.name:*psexec* OR process.name:*PsExec* OR process.name:*psExec* OR process.name:*Psexec* OR process.command_line:*psexec* OR process.command_line:*PSEXESVC* OR winlog.event_data.Image:*psexec* OR winlog.event_data.ServiceName:*PSEXESVC* OR winlog.event_data.ImageLoaded:*psexec* OR winlog.event_data.CommandLine.keyword:*psexec*) or (event.code:5145 AND (winlog.event_data.RelativeTargetName:*stdin* OR winlog.event_data.RelativeTargetName:*psexexsvc* OR winlog.event_data.RelativeTargetName:*PSEXESVC*))

agent.name: exists and winlog.event_data.LogonType: 10 and winlog.event_data.TargetUserName: exists and source.ip: exists -> rdp
