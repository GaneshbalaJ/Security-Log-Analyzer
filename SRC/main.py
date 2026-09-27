from datetime import datetime
from log_parser import parse_log_file
from detector import detect_suspicious_ips

def analyze(entries):
    total = len(entries)
    successful = 0
    failed = 0
    failed_by_ip = {}

    for entry in entries:
        if entry["event"] == "LOGIN SUCCESS":
            successful += 1
        elif entry["event"] == "LOGIN FAILED":
            failed += 1
            ip = entry["ip"]
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "failed_by_ip": failed_by_ip
    }

def write_report(stats, suspicious_ips, filepath="Reports/security_report.txt"):
    with open(filepath, "w") as file:
        file.write("SECURITY LOG ANALYSIS REPORT\n")
        file.write(f"Scan Date/Time: {datetime.now()}\n")
        file.write("----------------------------------------\n")
        file.write(f"Total Events: {stats['total']}\n")
        file.write(f"Successful Logins: {stats['successful']}\n")
        file.write(f"Failed Logins: {stats['failed']}\n\n")
        
        if suspicious_ips:
            file.write("SUSPICIOUS IP ADDRESSES\n")
            file.write("----------------------------------------\n")
            for item in suspicious_ips:
                file.write(f"- {item['ip']} ({item['failed_attempts']} failed attempts)\n")
                file.write("  (Reason: repeated failed logins, possible brute-force)\n")
        else:
            file.write("No suspicious activity detected.\n")

def main():
    entries = parse_log_file("Logs/Security.log")
    stats = analyze(entries)
    suspicious_ips = detect_suspicious_ips(stats["failed_by_ip"])

    print("Total Login Attempts:", stats["total"])
    print("Successful Logins:", stats["successful"])
    print("Failed Logins:", stats["failed"])

    if suspicious_ips:
        print("\n⚠️ Suspicious Activity Detected")
        for item in suspicious_ips:
            print(f"IP Address: {item['ip']}")
            print(f"Failed Attempts: {item['failed_attempts']}")
            print("Risk: Possible brute-force activity\n")
    else:
        print("\nNo suspicious activity detected.")
        
    write_report(stats, suspicious_ips)
    print("\nReport saved to Reports/security_report.txt")

if __name__ == "__main__":
    main()
