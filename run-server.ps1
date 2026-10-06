# Launch ATIE Web Operations Center Server
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   Starting ATIE Cybersecurity Operations Center (Web Server)         " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Dashboard will be live at: http://localhost:8080/`n" -ForegroundColor Yellow

if (Test-Path "$ScriptDir\target\classes\com\cybersecurity\engine\web\WebServerLauncher.class") {
    java -cp "$ScriptDir\target\classes" com.cybersecurity.engine.web.WebServerLauncher $args
} else {
    Write-Host "Classes not found. Compiling and running via Maven..." -ForegroundColor Cyan
    & "$ScriptDir\apache-maven-3.9.8\bin\mvn.cmd" compile exec:java -Dexec.mainClass="com.cybersecurity.engine.web.WebServerLauncher"
}
