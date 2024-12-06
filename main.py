# Import necessary libraries
import pandas as pd
import numpy as np
from tqdm import tqdm

# Generator function for log file processing
def parse_log_file(file_name):
    """
    Reads an HTTP request log file line by line using a generator.

    Args:
        file_name (str): Path to the log file.

    Yields:
        tuple: Parsed log entry components.
    """
    try:
        with open(file_name, 'r') as file:
            for line in tqdm(file, desc="Parsing log data"):
                parts = line.split(" ", 10)
                if len(parts) < 9:
                    continue  # Skip malformed lines

                # Extract components
                ip = parts[0]
                timestamp = parts[3].strip("[")
                timezone = parts[4].strip("]")
                method = parts[5].strip('"')
                url = parts[6]
                protocol = parts[7].strip('"')
                status = parts[8]
                size = parts[9].strip("\n") if len(parts) > 9 else np.nan
                message = parts[10].strip("\n").strip('"').strip('"') if len(parts) > 10 else np.nan

                yield (ip, timestamp, timezone, method, url, protocol, status, size, message)
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Function to convert generator output to a DataFrame
def convert_log_to_dataframe(file_name):
    """
    Converts parsed log entries into a Pandas DataFrame.

    Args:
        file_name (str): Path to the log file.

    Returns:
        pd.DataFrame: DataFrame containing parsed log data.
    """
    data_rows = list(parse_log_file(file_name))
    columns = ["IP Address", "Timestamp", "Timezone", "Method", "URL", "Protocol", "Status", "Size", "Message"]
    return pd.DataFrame(data_rows, columns=columns)

# Function to calculate the number of requests per IP address
def calculate_requests_per_ip(data):
    """
    Counts requests per IP address.
    
    Args:
        data (pd.DataFrame): DataFrame containing log data.
    
    Returns:
        pd.DataFrame: DataFrame of IP addresses and their request counts.
    """
    ip_requests = data.groupby("IP Address").size().reset_index(name="Request Count")
    ip_requests = ip_requests.sort_values(by="Request Count", ascending=False).reset_index(drop=True)

    # Optimise way to printing output
    # print(ip_requests.to_string(index=False))

    # Print the results in the specified format (mention in the assignment)
    print("IP Address           Request Count")
    for index, row in ip_requests.iterrows():
        print(f"{row["IP Address"]:<20} {row["Request Count"]}")
    return ip_requests


# Function to identify the most accessed endpoint
def find_most_accessed_endpoint(data):
    """
    Finds the most accessed URL endpoint.
    
    Args:
        data (pd.DataFrame): DataFrame containing log data.
    
    Returns:
        pd.DataFrame: DataFrame of the most accessed endpoint and its count.
    """
    endpoint_counts = data.groupby("URL").size().reset_index(name="Access Count")
    endpoint_counts = endpoint_counts.sort_values(by="Access Count", ascending=False).reset_index(drop=True)

    # Print the results in the specified format (mention in the assignment)
    print("\nMost Accessed Endpoint:")
    print(f"{endpoint_counts.iloc[0, 0]} (Accessed {endpoint_counts.iloc[0, 1]} times)")
    return endpoint_counts.head(1)


# Function to detect suspicious activity (e.g., failed login attempts)
def detect_suspicious_activity(data,threshold_attempt):
    """
    Identifies IPs with multiple failed login attempts (HTTP 401 status).
    
    Args:
        data (pd.DataFrame): DataFrame containing log data.
    
    Returns:
        pd.DataFrame: DataFrame of IPs with failed login attempt counts.
    """
    failed_attempts = data[(data["Status"] == "401") | (data["Message"] == "Invalid credentials")]
    failed_attempts = failed_attempts.groupby("IP Address").size().reset_index(name="Failed Login Attempts")
    failed_attempts = failed_attempts.sort_values(by="Failed Login Attempts", ascending=False).reset_index(drop=True)
    failed_attempts = failed_attempts[failed_attempts["Failed Login Attempts"] > threshold_attempt]
    # Print the results
    print("\nSuspicious Activity Detected:")

    # Optimise way to printing output
    # print(failed_attempts.to_string(index=False))

    # Print the results in the specified format (mention in the assignment)
    print("IP Address           Failed Login Attempts")
    for index, row in failed_attempts.iterrows():
        print(f"{row['IP Address']:<20} {row["Failed Login Attempts"]}")

    return failed_attempts.head(1)


# Function to save results into a single CSV file
def save_analysis_to_csv(log_file, output_file,threshold_attempt=10):
    """
    Processes an HTTP log file and saves analysis results to a CSV file.
    
    Args:
        log_file (str): Path to the HTTP log file.
        output_file (str): Path to the output CSV file.
    """
    log_data = convert_log_to_dataframe(log_file)

    if log_data.empty:
        print("No data to process. Exiting.")
        return

    requests_per_ip = calculate_requests_per_ip(log_data)
    most_accessed = find_most_accessed_endpoint(log_data)
    suspicious_activity = detect_suspicious_activity(log_data,threshold_attempt)


    with open(output_file, "w") as file:
        file.write("Requests per IP\n")
        requests_per_ip.to_csv(file, index=False)
        file.write("\nMost Accessed Endpoint\n")
        most_accessed.to_csv(file, index=False)
        file.write("\nSuspicious Activity\n")
        suspicious_activity.to_csv(file, index=False)

    print(f"\nAnalysis results saved to '{output_file}'.")


# Driver Code
if __name__ == "__main__":
    # Specify the path to the log file in the LOG_FILE variable
    # e.g., LOG_FILE = "/Users/krishna/Desktop/vrv/sample.log"
    LOG_FILE = "/Users/krishna_macbook/Desktop/vrv_assignment_krishna_singh/sample_log_files/sample.log"
    OUTPUT_FILE = "log_analysis_results.csv"
    FLAGGING_IP_THRESHOLD_ATTEMPT=10
    save_analysis_to_csv(LOG_FILE, OUTPUT_FILE,FLAGGING_IP_THRESHOLD_ATTEMPT)
