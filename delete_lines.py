import sys

def delete_lines(file_path, ranges):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Ranges are 1-indexed, inclusive
    lines_to_keep = []
    for i, line in enumerate(lines, 1):
        keep = True
        for start, end in ranges:
            if start <= i <= end:
                keep = False
                break
        if keep:
            lines_to_keep.append(line)
            
    with open(file_path, 'w') as f:
        f.writelines(lines_to_keep)

ranges = [
    (2455, 2462),
    (2471, 2487),
    (3192, 3431),
    (3464, 3579)
]

delete_lines("server/agents/assistant/agent.py", ranges)
