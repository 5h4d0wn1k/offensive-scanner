@echo off
REM Offensive Scanner Simplified Command Runner

if "%1"=="" goto help
if "%1"=="help" goto help

set JAR=target\offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar
set TARGET=%1
set COMMAND=

if "%2"=="port" (
    set COMMAND=-p
    echo Running port scan against %TARGET%...
) else if "%2"=="web" (
    set COMMAND=-w
    echo Running web scan against %TARGET%...
) else if "%2"=="full" (
    set COMMAND=-f
    echo Running full scan against %TARGET%...
) else if "%2"=="service" (
    set COMMAND=-s
    echo Running service enumeration against %TARGET%...
) else if "%2"=="net" (
    set COMMAND=-d
    echo Running network discovery against %TARGET%...
) else if "%2"=="dns" (
    set COMMAND=--dns-enum
    echo Running DNS enumeration against %TARGET%...
) else if "%2"=="vuln" (
    set COMMAND=-v
    echo Running vulnerability scan against %TARGET%...
) else if "%2"=="brute" (
    set COMMAND=-b
    echo Running brute force attack against %TARGET%...
) else (
    echo Unknown scan type: %2
    goto help
)

if "%3"=="report" (
    echo Report will be generated.
    java -jar %JAR% -t %TARGET% %COMMAND% -r
) else (
    java -jar %JAR% -t %TARGET% %COMMAND%
)

goto end

:help
echo Simple Offensive Scanner Commands
echo.
echo Usage: scan.bat TARGET SCAN_TYPE [report]
echo.
echo TARGET:      IP address, hostname, or IP range
echo SCAN_TYPE:   Type of scan to run:
echo              - port    (Port scanning)
echo              - web     (Web application scanning)
echo              - service (Service enumeration)
echo              - vuln    (Vulnerability scanning)
echo              - net     (Network discovery)
echo              - dns     (DNS enumeration)
echo              - brute   (Brute force attacks)
echo              - full    (Full scan - all modules)
echo report:      Add this to generate a report
echo.
echo Examples:
echo   scan.bat 192.168.31.1 port
echo   scan.bat example.com web report
echo   scan.bat 192.168.31.0/24 net
echo   scan.bat 192.168.31.1 full report
echo.

:end 