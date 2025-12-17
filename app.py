import os
import re
import json
import gzip
import logging
import logging.handlers
from datetime import datetime
from dotenv import load_dotenv
import paramiko
from scp import SCPClient
import jwt

# Load environment variables
load_dotenv()

# Configuration
SSH_HOST = os.getenv('SSH_HOST')
SSH_USER = os.getenv('SSH_USER')
SSH_PASS = os.getenv('SSH_PASS')
REMOTE_LOG_PATH = os.getenv('REMOTE_LOG_PATH')
LOCAL_LOG_PATH = os.getenv('LOCAL_LOG_PATH', './logs/')
JWT_SECRET = os.getenv('JWT_SECRET')
DATA_OUTPUT_PATH = './data/'

# Setup Logging to Syslog
logger = logging.getLogger('LogTranscriber')
logger.setLevel(logging.DEBUG)

syslog_handler = None
try:
    if os.path.exists('/dev/log'):
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    elif os.path.exists('/var/run/syslog'):
        syslog_handler = logging.handlers.SysLogHandler(address='/var/run/syslog')
    else:
        # Fallback for macOS UDP syslog (standard on newer macOS)
        syslog_handler = logging.handlers.SysLogHandler(address=('localhost', 514))

    if syslog_handler:
        formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
    else:
        print("Syslog socket not found. Logging to console only.")
except Exception as e:
    print(f"Failed to setup syslog: {e}. Logging to console only.")

# Also log to console for immediate feedback during dev
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(name)s: [%(levelname)s] %(message)s'))
logger.addHandler(console_handler)

def fetch_logs():
    """
    Connects to the remote server via SSH/SCP and downloads .gz log files.
    """
    logger.info("Starting log fetch process.")
    
    if not os.path.exists(LOCAL_LOG_PATH):
        os.makedirs(LOCAL_LOG_PATH)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(SSH_HOST, username=SSH_USER, password=SSH_PASS)
        logger.info(f"Connected to {SSH_HOST}")

        # SCP Client
        with SCPClient(ssh.get_transport()) as scp:
            # We need to list files first to find .gz files or just try to get them.
            # Since SCP doesn't support wildcards directly in all implementations easily without shell expansion,
            # we'll execute a command to find files first.
            stdin, stdout, stderr = ssh.exec_command(f"ls {REMOTE_LOG_PATH}access.log.*.gz")
            files = stdout.read().decode().splitlines()
            
            if not files:
                logger.warning(f"No .gz files found in {REMOTE_LOG_PATH}")
                return

            for file_path in files:
                file_name = os.path.basename(file_path)
                local_file = os.path.join(LOCAL_LOG_PATH, file_name)
                
                logger.info(f"Downloading {file_path} to {local_file}")
                try:
                    scp.get(file_path, local_file)
                    logger.info(f"Successfully downloaded {file_name}")
                except Exception as e:
                    logger.error(f"Failed to download {file_name}: {e}")

    except paramiko.AuthenticationException:
        logger.error("Authentication failed, please verify your credentials")
    except paramiko.SSHException as sshException:
        logger.error(f"Unable to establish SSH connection: {sshException}")
    except Exception as e:
        logger.error(f"Unexpected error in fetch_logs: {e}")
    finally:
        ssh.close()
        logger.info("SSH connection closed.")

def decode_token(token):
    """
    Decodes the JWT token using the secret.
    """
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return {"error": "Token expired"}
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return {"error": "Invalid token"}
    except Exception as e:
        logger.error(f"Error decoding token: {e}")
        return {"error": str(e)}

def parse_log_line(line):
    """
    Parses a single line of Nginx log.
    Returns a dictionary with extracted info or None if not matched.
    """
    # Regex for Nginx combined log format
    # Example: 181.74.37.7 - - [09/Dec/2025:04:43:12 -0300] "GET /url?t=... HTTP/1.1" 200 2880 "-" "UserAgent"
    log_pattern = re.compile(
        r'(?P<ip>[\d\.]+) - - \[(?P<date>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) HTTP/[0-9\.]+" (?P<status>\d+) (?P<bytes>\d+) "[^"]+" "(?P<user_agent>[^"]+)"'
    )
    
    try:
        match = log_pattern.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Extract 't' parameter from URL
        url = data['url']
        t_value = None
        if '?t=' in url or '&t=' in url:
            # Simple extraction of t parameter
            # Assuming t is the parameter name as per request
            query_match = re.search(r'[?&]t=([^&]+)', url)
            if query_match:
                t_value = query_match.group(1)
        
        if t_value:
            decoded_t = decode_token(t_value)
            data['t_decoded'] = decoded_t
            data['t_raw'] = t_value
        else:
            data['t_decoded'] = None
            data['t_raw'] = None

        return data

    except Exception as e:
        logger.warning(f"Error parsing line: {line[:50]}... Error: {e}")
        return None

def process_logs():
    """
    Iterates through local .gz logs, parses them, and aggregates data.
    """
    logger.info("Starting log processing.")
    
    if not os.path.exists(DATA_OUTPUT_PATH):
        os.makedirs(DATA_OUTPUT_PATH)

    aggregated_data = {}

    # List all .gz files in local log path
    try:
        log_files = [f for f in os.listdir(LOCAL_LOG_PATH) if f.endswith('.gz')]
    except FileNotFoundError:
        logger.error(f"Local log path {LOCAL_LOG_PATH} not found.")
        return

    for log_file in log_files:
        file_path = os.path.join(LOCAL_LOG_PATH, log_file)
        logger.info(f"Processing file: {file_path}")
        
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    parsed_data = parse_log_line(line)
                    
                    if parsed_data and parsed_data.get('t_decoded') and 'error' not in parsed_data['t_decoded']:
                        # Parse date to use as key
                        # Date format in log: 09/Dec/2025:04:43:12 -0300
                        try:
                            log_date_str = parsed_data['date'].split(':')[0] # 09/Dec/2025
                            date_obj = datetime.strptime(log_date_str, '%d/%b/%Y')
                            date_key = date_obj.strftime('%Y-%m-%d')
                            
                            if date_key not in aggregated_data:
                                aggregated_data[date_key] = []
                            
                            aggregated_data[date_key].append(parsed_data)
                            
                        except Exception as e:
                            logger.warning(f"Error parsing date from {parsed_data['date']}: {e}")
                            
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")

    # Write aggregated data to JSON files
    for date_key, entries in aggregated_data.items():
        output_file = os.path.join(DATA_OUTPUT_PATH, f"{date_key}.json")
        logger.info(f"Writing {len(entries)} entries to {output_file}")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=4)
        except Exception as e:
            logger.error(f"Error writing to {output_file}: {e}")

    logger.info("Log processing complete.")

if __name__ == "__main__":
    # 1. Fetch Logs
    fetch_logs()
    
    # 2. Process Logs
    process_logs()
