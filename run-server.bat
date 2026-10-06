@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo    Starting ATIE Cybersecurity Operations Center (Web Server)
echo ======================================================================
echo Dashboard will be available at: http://localhost:8080/
echo.

if exist "target\classes\com\cybersecurity\engine\web\WebServerLauncher.class" (
    java -cp target\classes com.cybersecurity.engine.web.WebServerLauncher %*
) else (
    echo Target classes not found, building and running via Maven...
    call "apache-maven-3.9.8\bin\mvn.cmd" compile exec:java -Dexec.mainClass="com.cybersecurity.engine.web.WebServerLauncher"
)

pause
