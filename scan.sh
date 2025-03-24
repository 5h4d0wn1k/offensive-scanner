#!/bin/bash
# Offensive Scanner Simplified Command Runner

if [ "$1" = "" ] || [ "$1" = "help" ]; then
    echo "Simple Offensive Scanner Commands"
    echo ""
    echo "Usage: ./scan.sh TARGET SCAN_TYPE [report]"
    echo ""
    echo "TARGET:      IP address, hostname, or IP range"
    echo "SCAN_TYPE:   Type of scan to run:"
    echo "             - port    (Port scanning)"
    echo "             - web     (Web application scanning)"
    echo "             - service (Service enumeration)"
    echo "             - vuln    (Vulnerability scanning)"
    echo "             - net     (Network discovery)"
    echo "             - dns     (DNS enumeration)"
    echo "             - brute   (Brute force attacks)"
    echo "             - full    (Full scan - all modules)"
    echo "report:      Add this to generate a report"
    echo ""
    echo "Examples:"
    echo "  ./scan.sh 192.168.1.1 port"
    echo "  ./scan.sh example.com web report"
    echo "  ./scan.sh 192.168.1.0/24 net"
    echo "  ./scan.sh 192.168.1.1 full report"
    echo ""
    exit 0
fi

JAR="target/offensive-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar"
TARGET="$1"
COMMAND=""

case "$2" in
    "port")
        COMMAND="-p"
        echo "Running port scan against $TARGET..."
        ;;
    "web")
        COMMAND="-w"
        echo "Running web scan against $TARGET..."
        ;;
    "full")
        COMMAND="-f"
        echo "Running full scan against $TARGET..."
        ;;
    "service")
        COMMAND="-s"
        echo "Running service enumeration against $TARGET..."
        ;;
    "net")
        COMMAND="-d"
        echo "Running network discovery against $TARGET..."
        ;;
    "dns")
        COMMAND="--dns-enum"
        echo "Running DNS enumeration against $TARGET..."
        ;;
    "vuln")
        COMMAND="-v"
        echo "Running vulnerability scan against $TARGET..."
        ;;
    "brute")
        COMMAND="-b"
        echo "Running brute force attack against $TARGET..."
        ;;
    *)
        echo "Unknown scan type: $2"
        exit 1
        ;;
esac

if [ "$3" = "report" ]; then
    echo "Report will be generated."
    java -jar "$JAR" -t "$TARGET" "$COMMAND" -r
else
    java -jar "$JAR" -t "$TARGET" "$COMMAND"
fi 