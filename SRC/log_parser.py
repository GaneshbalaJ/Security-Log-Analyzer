def parse_line(line):
    parts = line.strip().split(",")
    return {
        "timestamp": parts[0],
        "ip": parts[1],
        "event": parts[2],
        "username": parts[3]
    }

def parse_log_file(filepath):
    entries = []
    with open(filepath, "r") as file:
        for line in file:
            if line.strip(): # skip empty lines
                entries.append(parse_line(line))
    return entries
