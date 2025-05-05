# simple-querys-siem
simple hunting siem


- error.message: "whoami" or error.message: "curl"
- event.action: "SuspiciousActivity"
- event.action: "DLPRuleMatch"
- message: "Bad Robot"
- message: "backdoor: Mirai.Botnet"
- "web_app2: Cross.Site.Scripting"
- event.action: "CommandAndControl"
- "curl" or "wget" or "netcat"
- auditd.log.proctitle: "whoami" or process.args: "whoami" or process.executable: "whoami" or process.command_line: "whoami" or file.name: "whoami.exe"
- RunAsInvoker
- process.name : "runas.exe"
- file.name: "runas.exe"
- message: "applications3"
