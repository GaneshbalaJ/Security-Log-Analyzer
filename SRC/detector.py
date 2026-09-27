def detect_suspicious_ips(failed_by_ip, threshold=3):
    suspicious = []
    for ip, count in failed_by_ip.items():
        if count >= threshold:
            suspicious.append({"ip": ip, "failed_attempts": count})
    return suspicious
