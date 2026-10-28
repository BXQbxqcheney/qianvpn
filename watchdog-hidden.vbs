CreateObject("WScript.Shell").Run "node """ & Replace(WScript.ScriptFullName, "watchdog-hidden.vbs", "watchdog.js") & """", 0, False
