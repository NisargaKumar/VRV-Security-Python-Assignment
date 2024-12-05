import re
import csv
from collections import defaultdict

def count_requests_per_ip(log_lines):
    # Initialize a dictionary to count requests per IP address
    ip_counts = defaultdict(int)
    for line in log_lines:
        # Match the log line pattern to extract the IP address
        match = re.match(r'(\S+) - - \[.*\] ".*" \d+ \d+', line)
        if match:
            ip_address = match.group(1)
            # Increment the request count for the extracted IP address
            ip_counts[ip_address] += 1
    return ip_counts

def most_accessed_endpoint(log_lines):
    # Initialize a dictionary to count accesses to endpoints
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        # Match the log line pattern to extract the endpoint
        match = re.match(r'.*"(\S+ \S+).*" \d+ \d+', line)
        if match:
            endpoint = match.group(1).split()[1]
            # Increment the access count for the extracted endpoint
            endpoint_counts[endpoint] += 1
    if endpoint_counts:
        # Determine the most accessed endpoint
        most_accessed = max(endpoint_counts, key=endpoint_counts.get)
        return most_accessed, endpoint_counts[most_accessed]
    return None, 0

def detect_suspicious_activity(log_lines, threshold=3):
    # Initialize a dictionary to count failed login attempts per IP address
    failed_logins = defaultdict(int)
    for line in log_lines:
        # Match the log line pattern to identify failed login attempts (401 status)
        match = re.match(r'(\S+) - - \[.*\] ".*" 401 .*', line)
        if match:
            ip_address = match.group(1)
            # Increment the failed login count for the extracted IP address
            failed_logins[ip_address] += 1
    # Identify IPs with failed login attempts above the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= threshold}
    return suspicious_ips

def process_log_file(file_path):
    # Read log lines from the specified file
    with open(file_path, 'r') as file:
        log_lines = file.readlines()

    # Process log lines to gather analysis data
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed, access_count = most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)

    return ip_counts, most_accessed, access_count, suspicious_activity

def write_results_to_csv(ip_counts, most_accessed, access_count, suspicious_activity):
    # Write the analysis results to a CSV file
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['Requests per IP:'])
        writer.writerow(['IP Address', 'Request Count'])
        # Sort IP counts in descending order and write to CSV
        for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([]) # Add a blank row for separation

        writer.writerow(['Most Accessed Endpoint:'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed, access_count])

        writer.writerow([])

        writer.writerow(['Suspicious Activity:'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        # Write suspicious activity counts to CSV
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def print_results(ip_counts, most_accessed, access_count, suspicious_activity):
    # Print the analysis results to the console
    print('Requests per IP:')
    print('IP Address           Request Count')
    # Sort IP counts in descending order and print to console
    for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
        print(f'{ip:<20} {count}')

    print('\nMost Accessed Endpoint:')
    print(f'{most_accessed} (Accessed {access_count} times)')

    if suspicious_activity:
        print('\nSuspicious Activity Detected:')
        print('IP Address           Failed Login Attempts')
        # Print suspicious activity details
        for ip, count in suspicious_activity.items():
            print(f'{ip:<20} {count}')
    else:
        print('\nNo suspicious activity detected.')

def main():
    # Specify the log file path
    file_path = 'sample.log'
    # Process the log file and gather analysis data
    ip_counts, most_accessed, access_count, suspicious_activity = process_log_file(file_path)

    # Print and write results
    print_results(ip_counts, most_accessed, access_count, suspicious_activity)
    write_results_to_csv(ip_counts, most_accessed, access_count, suspicious_activity)

if __name__ == '__main__':
    main()
