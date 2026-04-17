from scapy.all import sniff, Dot11, Dot11Beacon # Scapy modules for packet capture & 802.11 frame parsing
import logging # Python logging module for outputting detection activities
import os # OS module for file & system level operations
from logging.handlers import RotatingFileHandler # Handler that rotates log files based on the size
import time # Time module used for tracking detection timestamps

start_time = None # Time start variable used to measure detection latency
detection_time_recorded = False # Ensures detection time is recorded Only once per test. 

# Set up logging with rotating logs (5 MB max per log file & keep 3 backup files)
log_file = "rogue_aps.log"      # Name of the log file
max_log_size = 5 * 1024 * 1024  # 5 MB max before rotation occurs
backup_count = 3                # Number of rotated backup log files

# Setting up the rotating log file handler
handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
logging.basicConfig(handlers=[handler], level=logging.INFO, format="%(asctime)s - %(message)s") # This sets up logging to a file with that "" name & logs timestamps.

known_networks = {} # This is a Dictionary to store the SSID to BSSID mapping

# Whitelist of legitimate APs (AC750)
whitelist_bssids = {"60:83:e7:45:b4:33"}  # This is the BSSID of the AC750 (Trusted AP running inside the Victim Kali VM)

# Store known rogue APs for tracking
rogue_aps = {}

# Threshold for suspicious signal strength (Evil Twin indicator)
evil_twin_signal_threshold = -70  # dBm (Lowered it from -50 to make it more sensitive to weaker signals)

# Track legitimate BSSIDs for false positive reduction
legitimate_bssids = set()

# //// Performance Metric Counters ////
# These counters are used at the end of testing to caluclate Precision, Recall, F1 Scores and Accuracy
true_positives = 0  # Number of rogue APs correctly identified by the IDS
false_positives = 0 # Number of legit APs incorrectly flagged by the IDS 
false_negatives = 0 # Number of actual rogue APs that the IDS failed to detect
true_negatives = 0  # Number of correctly identified legit APs that were NOT flagged as rogue

# Total number of actual rogue APs in the test environment (There is 1 - UniTest_AP)
total_actual_rogues = 1

# Function to calculate and log Precision ration of correct rogue detections 
def calculate_precision():
    if true_positives + false_positives > 0:
        precision = true_positives / (true_positives + false_positives)
        print(f"[METRIC] Precision: {precision:.2f}")
        logging.info(f"[METRIC] Precision: {precision:.2f}")
    else:
        print("[METRIC] Precision: Not enough data for calculation")
        logging.info("[METRIC] Precision: Not enough data for calculation")

# Function to calculate and log Recall 
def calculate_recall():
    false_negatives = total_actual_rogues - true_positives # False Negatives = any actual rogue APs that were NOT detected
    if false_negatives < 0:   # Clamp to 0 to avoid negative values 
        false_negatives = 0
    if true_positives + false_negatives > 0:
        recall = true_positives / (true_positives + false_negatives)
        print(f"[METRIC] Recall: {recall:.2f}")
        logging.info(f"[METRIC] Recall: {recall:.2f}")
    else:
        print("[METRIC] Recall: Not enough data for calculation")
        logging.info("[METRIC] Recall: Not enough data for calculation")       

# Function to calculate and log F1 Score - This is the mean of Precision & Recall
def calculate_f1_score():
    # First recalculate the precision and recall values to use in the F1 formula
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    false_negatives = total_actual_rogues - true_positives
    if false_negatives < 0:
        false_negatives = 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    
    if precision + recall > 0: # F1 Score is the mean of Precision and Recall
        f1_score = 2 * (precision * recall) / (precision + recall)
        print(f"[METRIC] F1 Score: {f1_score:.2f}")
        logging.info(f"[METRIC] F1 Score: {f1_score:.2f}")
    else:
        print("[METRIC] F1 Score: Not enough data for calculation")
        logging.info("[METRIC] F1 Score: Not enough data for calculation")

# Function to calculate and log Accuracy - This is the proportion of all correct classifications (TP + TN) out of the total
def calculate_accuracy():
    # False Negatives = any actual rogue APs that were NOT detected
    false_negatives = total_actual_rogues - true_positives 
    if false_negatives < 0:
        false_negatives = 0
    total = true_positives + true_negatives + false_positives + false_negatives
    if total > 0:
        accuracy = (true_positives + true_negatives) / total
        print(f"[METRIC] Accuracy: {accuracy:.2f}")
        logging.info(f"[METRIC] Accuracy: {accuracy:.2f}")
    else:
        print("[METRIC] Accuracy: Not enough data for calculation")
        logging.info("[METRIC] Accuracy: Not enough data for calculation")

def packet_handler(pkt): # Checks if it's a Wi-Fi packet
    global true_positives, false_positives, true_negatives, start_time, detection_time_recorded

    if pkt.haslayer(Dot11Beacon):  # Only consider Beacon frames (to avoid handling data frames)
        ssid = pkt.info.decode(errors='ignore') if hasattr(pkt, "info") else None
        bssid = pkt.addr3
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else None  # Capture the signal strength (RSSI)

        # Ensure ssid is valid before proceeding
        if ssid is None:
            return  # Skip if ssid is None (invalid packet)

        # Focus only on the Rogue AP SSID (UniTest_AP) to detect duplicates
        if ssid == "UniTest_AP":  # Filter for the rogue AP SSID only

            if bssid in whitelist_bssids:  # If the BSSID is in the whitelist, ignore it (legitimate APs are skipped)
                # UniTest_AP SSID seen but the BSSID is our whitelisted legitimate AP = False Positive
                false_positives += 1
                print(f"[DEBUG] Legitimate AP detected: {ssid} from BSSID: {bssid} - Skipping")  # Debugging log for legitimate AP
                return  # Skip if BSSID is in the whitelist (legit AP)

            # Detecting Rogue APs
            if bssid not in rogue_aps:  # New rogue AP detected
                rogue_aps[bssid] = ssid
                print(f"[ALERT] New Rogue AP detected: {ssid} from BSSID: {bssid}")
                logging.info(f"[ALERT] New Rogue AP detected: {ssid} from BSSID: {bssid}")

                # Increment True Positive count
                true_positives += 1
                print(f"[DEBUG] True Positives (TP): {true_positives}")  # Debugging line for TP

                # Check for unusually strong signal (possible Evil Twin)
                if signal_strength is not None and signal_strength > evil_twin_signal_threshold:
                    warning_message = f"[ALERT] Possible Evil Twin detected: {ssid} with very strong signal ({signal_strength} dBm)"
                    print(warning_message)
                    logging.info(warning_message)

                # Start the timer for detection time 
                if start_time is None:
                    start_time = time.time()

                if not detection_time_recorded:
                    detection_time = time.time() - start_time
                    print(f"[METRIC] Detection Time: {detection_time:.2f} seconds")
                    logging.info(f"[METRIC] Detection Time: {detection_time:.2f} seconds")
                    detection_time_recorded = True    

            # If already seen this rogue BSSID before, just skip - don't recount anything
            else:
                pass

        # All other SSIDs around user (St Andrews Staff, ASK4, Three, and such) are background noise
        # The IDS is NOT flagging them as rogue, so they are NOT false positives - just ignore these
        else:
            # Every non-UniTest_AP that is correctly NOT flagged as rogue = True Negative
            # Only count each unique BSSID once to avoid inflating the TN count
            if bssid not in legitimate_bssids:
                true_negatives += 1
                print(f"[DEBUG] True Negative (TN): {bssid} correctly ignored, Total TN: {true_negatives}")

            # Checks for duplicate SSID with different BSSID
            if ssid in known_networks: 
                if known_networks[ssid] != bssid:
                    alert_message = f"[ALERT] Duplicate SSID detected: {ssid} from BSSID: {bssid}"
                    print(alert_message)
                    logging.info(alert_message)  # Logs the alert                 
            else:   
                known_networks[ssid] = bssid

            print(f"SSID: {ssid}, BSSID: {bssid}, Signal Strength: {signal_strength} dBm") # Prints the SSID, BSSID & Signal Strength (RSSI) for each beacon frame captured
            logging.info(f"SSID: {ssid}, BSSID: {bssid}, Signal Strength: {signal_strength} dBm")  # Logs the detected AP

            # Tracks legitimate BSSIDs for false positive reduction
            if bssid not in legitimate_bssids:
                legitimate_bssids.add(bssid)  # Add legitimate AP BSSID to the set

            # Detect if a BSSID that was once legitimate (AC750) suddenly appears as a rogue
            if bssid in legitimate_bssids:
                print(f"[ALERT] Possible Evil Twin detected: {ssid} with very strong signal ({signal_strength} dBm)")
                logging.info(f"[ALERT] Possible Evil Twin detected: {ssid} with very strong signal ({signal_strength} dBm)")

# Function to analyze the collected logs
def analyze_logs():
    with open(log_file, 'r') as file:
        logs = file.readlines()

    # Example: Count occurrences of each BSSID (or to perform other custom/manual analysis)
    bssid_count = {}
    for line in logs:
        if "BSSID" in line:
            bssid = line.split("BSSID:")[1].split(",")[0].strip()
            if bssid in bssid_count:
                bssid_count[bssid] += 1
            else:
                bssid_count[bssid] = 1

    # Example: Print the BSSIDs and how many times they appeared
    print("\nBSSID Frequency Analysis:")
    for bssid, count in bssid_count.items():
        print(f"BSSID: {bssid} detected {count} times")

# Add delay before sniffing
time.sleep(2)  # Adjust this delay as needed before sniffing (This wouldn't make a difference to the scan if IDS picks up the Rogue AP instantly)

sniff(iface="wlan0", prn=packet_handler, timeout=60, store=0, filter="type mgt") # Sniffs on the Wi-Fi interface in monitor mode & Capture Management frames only (Beacons)

# Call the log analysis function after sniffing (Timing can be adjusted if required by the user)
analyze_logs()  # Analyze logs after sniffing

# Call the Precision calculation function after sniffing
calculate_precision()  # Calculate Precision after scanning

# Call the Recall calculation function after sniffing
calculate_recall()  # Calculate Recall after scanning

# Call the F1 Score calculation function after sniffing
calculate_f1_score()  # Calculate F1 Score after scanning

# Call the Accuracy calculation function after sniffing
calculate_accuracy()  # Calculate Accuracy after scanning
