# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# OASIS Security & Remote Monitoring System
# -----------------------------------------------------------------------------
# Author: [Your Name/Organization]
# Date: [Date of Last Update]
# Version: 1.0
#
# Description:
# This script manages the operational modes of the OASIS security system,
# primarily based on presence detection from an LD2410C radar sensor
# (communicating via GPIO for basic presence and serial/UART for detailed data)
# and object detection events from a Frigate NVR system. It dynamically
# switches between 'PROACTIVE' and 'STANDBY' modes to optimize system
# resources (e.g., CPU usage, Frigate recording/detection).
#
# The manager also incorporates sensor fusion logic to detect potential
# "hidden intruder" scenarios (radar presence without camera confirmation)
# and "camera tamper" scenarios (radar presence with suspected camera blindness).
#
# Communication with other system components (e.g., Node-RED for UI/control)
# is handled via MQTT.
#
# Key Features:
# - Mode management (PROACTIVE/STANDBY) based on LD2410C radar.
# - Frigate NVR control (detection and recording on/off).
# - CPU governor adjustment for power saving.
# - MQTT integration for commands, status, sensor data, and alerts.
# - LD2410C serial data parsing for detailed radar information.
# - Sensor fusion for "hidden intruder" alerts.
# - Tamper detection for "camera blind" alerts.
# - Manual override of operational modes.
# - System arm/disarm functionality.
# - Comprehensive logging.
# -----------------------------------------------------------------------------

# --- Standard Library Imports ---
import time
import datetime
import os
import sys
import logging
import json
import threading

# --- Third-Party Library Imports ---
import paho.mqtt.client as mqtt # For MQTT communication
from paho.mqtt.client import CallbackAPIVersion # For MQTT callback API version
import RPi.GPIO as GPIO      # For Raspberry Pi GPIO interaction (LD2410C OUT pin)
import serial                # For serial communication (LD2410C UART)
import struct                # For unpacking binary data from LD2410C serial frames

# --- Configuration Constants ---

# Logging Configuration
LOG_FILE = "/home/pi/Desktop/OASIS/mode_manager_ld2410c_serial.log"  # Path to the main log file
LOG_LEVEL = logging.INFO  # Logging level (e.g., INFO, DEBUG, WARNING, ERROR)

# MQTT Broker Settings
MQTT_BROKER = "localhost"  # Address of the MQTT broker
MQTT_PORT = 1883  # Port for the MQTT broker
MQTT_CLIENT_ID = "OASIS_Mode_Manager_LD2410C_Serial"  # Unique client ID for this script
MQTT_USERNAME = None  # Username for MQTT broker (if any)
MQTT_PASSWORD = None  # Password for MQTT broker (if any)

# MQTT Topics
MQTT_TOPIC_COMMANDS = "oasis/security/commands"  # Topic for receiving commands (e.g., from Node-RED)
MQTT_TOPIC_STATUS = "oasis/security/status"  # Topic for publishing system status
MQTT_TOPIC_LD2410C_STATUS = "oasis/sensor/ld2410c/status"  # Topic for basic LD2410C presence (GPIO OUT pin)
MQTT_TOPIC_LD2410C_DETAILS = "oasis/sensor/ld2410c/details"  # Topic for detailed LD2410C data (UART)
MQTT_TOPIC_FRIGATE_EVENTS = "frigate/events"  # Topic for Frigate NVR object detection events [cite: 1]
MQTT_TOPIC_ALERTS = "oasis/srm/alerts"  # Centralized topic for fusion/tamper alerts [cite: 2]

# LD2410C Radar Sensor Settings
LD2410C_OUT_PIN = 17  # GPIO pin (BCM numbering) connected to the LD2410C 'OUT' pin
ENABLE_SERIAL_DEBUG = True  # Set to True to enable reading detailed data from LD2410C via UART
SERIAL_PORT = '/dev/ttyS0'  # Serial port for LD2410C UART (e.g., /dev/ttyS0 or /dev/serial0 on RPi)
BAUD_RATE = 256000  # Baud rate for LD2410C serial communication in reporting mode
FRAME_HEADER = b'\xFD\xFC\xFB\xFA'  # Start sequence for LD2410C data frames
FRAME_END = b'\x04\x03\x02\x01'  # End sequence for LD2410C data frames

# Frigate NVR Control Settings
FRIGATE_CAMERA_NAME = "pi_camera"  # Name of the camera in Frigate configuration
FRIGATE_TOPIC_DETECT_SET = f"frigate/{FRIGATE_CAMERA_NAME}/detect/set" # Topic to control Frigate detection
FRIGATE_TOPIC_RECORD_SET = f"frigate/{FRIGATE_CAMERA_NAME}/recordings/set" # Topic to control Frigate recording
FRIGATE_CONTROL_PAYLOAD_ON = "ON"  # Payload to turn Frigate detection/recording ON
FRIGATE_CONTROL_PAYLOAD_OFF = "OFF"  # Payload to turn Frigate detection/recording OFF

# Operational Mode Settings
DEFAULT_MODE = "STANDBY"  # Default operational mode on startup
CPU_GOVERNOR_PROACTIVE = "ondemand"  # CPU governor for PROACTIVE mode (performance-oriented)
CPU_GOVERNOR_STANDBY = "powersave"  # CPU governor for STANDBY mode (power-saving)
STATUS_PUBLISH_INTERVAL = 30  # Interval in seconds for periodic status publishing

# --- Global State Variables --- [cite: 3]
current_mode = DEFAULT_MODE  # Current operational mode of the system
manual_override_mode = None  # Stores the manually set override mode (if any)
ld2410c_presence_detected = False  # True if LD2410C OUT pin indicates presence (radar presence) [cite: 3]
last_status_publish_time = 0  # Timestamp of the last full status publish
mqtt_client_connected = False  # Flag indicating MQTT client connection status
mqtt_client_instance = None  # Instance of the MQTTClientWrapper
system_armed = True  # System armed state (True by default, can be changed via MQTT) [cite: 3]

# Serial Communication Globals (for LD2410C UART)
serial_port_instance = None  # Instance of the PySerial port
serial_thread = None  # Thread for reading serial data
serial_thread_running = False  # Flag to control the serial reader thread

# Sensor Fusion and Tamper Detection Globals
camera_detection = False  # True if Frigate detects a 'person' object [cite: 3]
last_camera_detection_time = 0  # Timestamp of the last camera 'person' detection event [cite: 3]
time_radar_became_active = 0  # Timestamp when radar (ld2410c_presence_detected) transitioned to True [cite: 3]

# Fusion Alert (Hidden Intruder) Variables
last_fusion_alert_time = 0  # Timestamp of the last fusion alert to manage cooldown

# Tamper Alert (Camera Blind) Variables
last_tamper_alert_time = 0  # Timestamp of the last tamper alert to manage cooldown
camera_blind = False  # True if camera is suspected to be blind/tampered [cite: 3]
# Timeout in seconds: if radar is active for this duration without any camera detection,
# the camera might be considered blind.
NO_DETECTION_WHILE_RADAR_TIMEOUT = 300  # 5 minutes [cite: 4]
last_camera_detection_time_with_radar = 0  # Timestamp of the last camera detection that occurred while radar was also active [cite: 4]

# General Alert Settings
ALERT_COOLDOWN = 60  # Cooldown period in seconds for both fusion and tamper alerts
FUSION_ALERT_LOG_FILE = "/var/log/fusion_alerts.log"  # Dedicated log file for fusion/tamper alerts [cite: 4]

# Loggers
fusion_logger = None  # Dedicated logger instance for fusion/tamper alerts

# --- Logging Setup ---
# Ensure the directory for the main log file exists
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):  # Check if log_dir is not an empty string (e.g., if LOG_FILE is in root) [cite: 4, 5]
    try:
        os.makedirs(log_dir) # Create log directory if it doesn't exist [cite: 5]
    except OSError as e:
        print(f"Error creating main log directory {log_dir}: {e}") # Print error if directory creation fails [cite: 5]

# Configure basic logging for the main application
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s %(levelname)-8s [%(threadName)s:%(filename)s:%(lineno)d] %(message)s', # Log message format
    datefmt='%Y-%m-%d %H:%M:%S', # Timestamp format
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),  # Log to file (append mode)
        logging.StreamHandler(sys.stdout)  # Log to standard output (console)
    ]
)

def setup_fusion_logger():
    """
    Sets up a dedicated logger for fusion and tamper alerts.
    This allows alert messages to be written to a separate file for easier monitoring.
    """
    global fusion_logger
    fusion_logger = logging.getLogger('FusionTamperLogger') # Get a named logger instance [cite: 5]
    fusion_logger.setLevel(logging.INFO) # Set logging level for this logger [cite: 6]
    # Prevent fusion_logger messages from propagating to the root logger (configured by basicConfig)
    # This ensures that fusion alerts are only logged to their dedicated file by this handler,
    # unless explicitly handled elsewhere.
    fusion_logger.propagate = False # [cite: 6]

    try:
        # Ensure the directory for the fusion alert log file exists
        fusion_log_dir = os.path.dirname(FUSION_ALERT_LOG_FILE)
        if fusion_log_dir and not os.path.exists(fusion_log_dir): # Check if fusion_log_dir is not an empty string [cite: 6]
            os.makedirs(fusion_log_dir, exist_ok=True) # Create directory, exist_ok=True prevents error if dir already exists [cite: 6, 7]

        # Create a file handler for the fusion logger
        fh = logging.FileHandler(FUSION_ALERT_LOG_FILE, mode='a') # Append mode [cite: 7]
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - Node: ' + MQTT_CLIENT_ID + ' - %(message)s', # Custom format for alert logs
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        fusion_logger.addHandler(fh) # Add handler to the fusion logger
        fusion_logger.info("Fusion/Tamper alert logger initialized.") # Log initialization [cite: 7]
    except Exception as e:
        # If dedicated logger setup fails, fusion/tamper alerts will use the main logger via log_alert_event fallback
        logging.error(f"Failed to setup fusion logger for {FUSION_ALERT_LOG_FILE}: {e}") # Log error [cite: 7, 8]
        fusion_logger = None # Reset to None so fallback mechanism is used [cite: 8]

def log_alert_event(message, level=logging.INFO):
    """
    Logs an alert event (fusion or tamper) to the dedicated fusion logger.
    If the dedicated logger is not available, it falls back to the main application logger.

    Args:
        message (str): The alert message to log.
        level (int, optional): The logging level (e.g., logging.INFO, logging.WARNING).
                               Defaults to logging.INFO.
    """
    logger_to_use = fusion_logger if fusion_logger else logging # Use dedicated logger if available, else main logger [cite: 8]
    # Prefix for fallback to make it clear it's an alert and identify the node
    prefix = f"Node: {MQTT_CLIENT_ID} - " if fusion_logger else f"ALERT_FALLBACK - Node: {MQTT_CLIENT_ID} - " # [cite: 8]

    full_message = f"{prefix if not fusion_logger else ''}{message}" # Construct full message [cite: 8, 9]

    if level == logging.WARNING:
        logger_to_use.warning(full_message) # Log as warning [cite: 9]
    else:  # Default to INFO
        logger_to_use.info(full_message) # Log as info [cite: 9]


# --- GPIO Setup (for LD2410C OUT Pin) ---
try:
    GPIO.setmode(GPIO.BCM)  # Use Broadcom SOC channel numbering for GPIO pins
    GPIO.setup(LD2410C_OUT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)  # Set pin as input with pull-down resistor
    GPIO.setwarnings(False)  # Disable GPIO warnings (e.g., "channel already in use")
    logging.info(f"GPIO pin {LD2410C_OUT_PIN} setup as input with pull-down for LD2410C OUT.") # [cite: 9]
except Exception as e:
    logging.critical(f"Failed to setup GPIO: {e}. Exiting.", exc_info=True) # Log critical error [cite: 9, 10]
    sys.exit(1)  # Critical failure, cannot proceed without GPIO for radar presence [cite: 10]

# --- Helper Functions ---
def set_cpu_governor(governor):
    """
    Sets the CPU frequency scaling governor using the `cpufreq-set` utility.
    Requires `cpufrequtils` to be installed and sudo privileges.

    Args:
        governor (str): The desired CPU governor (e.g., "ondemand", "powersave").
    """
    if not sys.platform.startswith('linux'):  # CPU governor setting is typically Linux-specific [cite: 10, 11]
        logging.debug("CPU governor setting skipped (not on Linux).") # [cite: 11]
        return

    # Check for cpufreq-set command existence only once for efficiency using a function attribute
    if not hasattr(set_cpu_governor, 'cmd_exists'):
        set_cpu_governor.cmd_exists = (os.system("command -v cpufreq-set > /dev/null") == 0) # Check if command exists [cite: 11]
        if not set_cpu_governor.cmd_exists:
            logging.warning("`cpufreq-set` command not found. Install 'cpufrequtils'. Cannot set CPU governor.") # [cite: 11, 12]

    if not set_cpu_governor.cmd_exists:  # If command doesn't exist, skip [cite: 12]
        return

    command = f"sudo cpufreq-set -g {governor}"  # Command requires sudo [cite: 12]
    logging.info(f"Attempting to set CPU governor to: {governor}") # [cite: 12]
    try:
        result = os.system(command) # Execute the command
        if result != 0:  # os.system returns 0 on success
            logging.warning(f"Failed to run `cpufreq-set -g {governor}` (exit code {result}). Check permissions or if governor '{governor}' is supported.") # [cite: 12, 13]
    except Exception as e:
        logging.error(f"Error executing cpufreq-set command: {e}") # [cite: 13]

# --- MQTT Client Wrapper Class ---
class MQTTClientWrapper:
    """
    A wrapper class to manage MQTT client connection, publishing, and subscriptions
    with automatic reconnection capabilities.
    """
    def __init__(self, broker, port, client_id, username, password, command_callback):
        """
        Initializes the MQTTClientWrapper.

        Args:
            broker (str): MQTT broker address.
            port (int): MQTT broker port.
            client_id (str): Unique client ID for MQTT connection.
            username (str): Username for MQTT authentication (or None).
            password (str): Password for MQTT authentication (or None).
            command_callback (function): Callback function to handle incoming MQTT commands.
        """
        self.broker = broker
        self.port = port
        self.client_id = client_id
        self.username = username # [cite: 13, 14]
        self.password = password # [cite: 14]
        self.command_callback = command_callback  # Function to call when a command is received on MQTT_TOPIC_COMMANDS [cite: 14]
        self.client = mqtt.Client(client_id=self.client_id,
                                   callback_api_version=CallbackAPIVersion.VERSION1, # Use Paho MQTT API v1 callbacks
                                   clean_session=True) # Use clean session

        # Assigning MQTT callback functions
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self._connect_thread = None  # Thread for handling blocking connect with retries [cite: 15]
        self.connected = False  # Flag to track MQTT connection status [cite: 15]

    def _on_connect(self, client, userdata, flags, rc):
        """
        Callback executed when the client successfully connects to the MQTT broker.
        """
        global mqtt_client_connected
        if rc == 0:  # Connection successful (rc=0)
            logging.info(f"MQTT connected successfully to broker {self.broker}:{self.port}") # [cite: 15]
            self.connected = True # [cite: 16]
            mqtt_client_connected = True # [cite: 16]

            # Subscribe to relevant topics upon successful connection
            client.subscribe(MQTT_TOPIC_COMMANDS)  # For receiving commands (e.g., from Node-RED) [cite: 16]
            logging.info(f"MQTT Subscribed to: {MQTT_TOPIC_COMMANDS}") # [cite: 16]

            client.subscribe(MQTT_TOPIC_FRIGATE_EVENTS)  # For Frigate object detection events [cite: 17]
            logging.info(f"MQTT Subscribed to: {MQTT_TOPIC_FRIGATE_EVENTS}") # [cite: 17]

            # Publish initial status now that we are connected
            publish_status() # Publish overall system status [cite: 17]
            publish_ld2410c_status()  # Publish initial radar GPIO status [cite: 17]
        else:  # Connection failed
            logging.error(f"MQTT connection failed with result code {rc}: {mqtt.connack_string(rc)}") # [cite: 18]
            self.connected = False # [cite: 18]
            mqtt_client_connected = False # [cite: 18]

    def _on_disconnect(self, client, userdata, rc):
        """
        Callback executed when the client disconnects from the MQTT broker.
        """
        global mqtt_client_connected
        logging.warning(f"MQTT disconnected with result code {rc}. Will attempt to reconnect via loop_start() if active, or _connect_blocking thread.") # [cite: 18, 19]
        self.connected = False # [cite: 19]
        mqtt_client_connected = False # [cite: 19]
        # The _connect_blocking thread (if started by connect_async) will handle reconnection attempts.

    def _on_message(self, client, userdata, msg):
        """
        Callback executed when a PUBLISH message is received from the broker
        on a subscribed topic.
        """
        global camera_detection, last_camera_detection_time, ld2410c_presence_detected
        global last_camera_detection_time_with_radar # For tamper logic

        topic = msg.topic
        payload_str = ""  # Initialize to empty string for safety [cite: 20]
        try:
            payload_str = msg.payload.decode('utf-8')  # Decode payload to string (assuming UTF-8) [cite: 20]

            if topic == MQTT_TOPIC_COMMANDS:  # Handle commands (e.g., from Node-RED) [cite: 20]
                logging.debug(f"Command received on {topic}: {payload_str}") # [cite: 20]
                command_data = json.loads(payload_str)  # Parse JSON command [cite: 21]
                self.command_callback(command_data)  # Call the registered command handler function [cite: 21]

            # Handle Frigate events (e.g., "frigate/events")
            # This checks if the message topic starts with the base of FRIGATE_TOPIC_EVENTS (e.g. "frigate")
            elif topic.startswith(MQTT_TOPIC_FRIGATE_EVENTS.split('/')[0]): # [cite: 21]
                logging.debug(f"Frigate event received on topic {topic}: {payload_str[:200]}...")  # Log a snippet of the payload [cite: 21, 22]
                event_data = json.loads(payload_str)  # Parse Frigate event JSON [cite: 22]

                event_type = event_data.get('type') # Get event type (e.g., 'new', 'update', 'end')

                # Check for person detection start ('new') or ongoing update ('update')
                if event_type == 'new' or event_type == 'update': # [cite: 22, 23]
                    if event_data.get('after', {}).get('label') == 'person':  # Check if the detected object is a 'person' [cite: 23]
                        if not camera_detection:  # Log only on state change to True
                            logging.info("Camera detection: Person event started/updated by Frigate.") # [cite: 23, 24]
                        camera_detection = True # [cite: 24]
                        last_camera_detection_time = time.time()  # Record time of this detection [cite: 24]
                        # If radar is also active at this moment, update the timestamp for tamper logic
                        if ld2410c_presence_detected: # [cite: 25]
                            last_camera_detection_time_with_radar = last_camera_detection_time # [cite: 25]

                # Check for person detection end ('end')
                elif event_type == 'end': # [cite: 26]
                    if event_data.get('before', {}).get('label') == 'person':  # Check if the ended event was for a 'person' [cite: 26]
                        # This means a specific 'person' event ID has ended.
                        # For simplicity in this manager, we assume no person is detected if *any* person event ends.
                        # A more complex system might track multiple distinct person event IDs.
                        if camera_detection:  # Log only on state change to False [cite: 29]
                             logging.info("Camera detection: Person event ended by Frigate.") # [cite: 29]
                        camera_detection = False # [cite: 29]
                        # last_camera_detection_time remains the time of the *last positive detection*. [cite: 29, 30]
            else:  # Unhandled topic
                logging.debug(f"Unhandled MQTT topic: {topic}") # [cite: 30]
        except json.JSONDecodeError:
            logging.error(f"Failed to decode JSON payload on topic {topic}: {payload_str}") # [cite: 30]
        except UnicodeDecodeError:
            logging.error(f"Failed to decode payload as UTF-8 on topic {topic}") # [cite: 30]
        except Exception as e:
            logging.error(f"Error processing MQTT message on topic {topic}: {e}", exc_info=True) # [cite: 30, 31]

    def connect_async(self):
        """
        Connects to the MQTT broker asynchronously by starting a new thread.
        This prevents the main application thread from blocking during connection attempts.
        """
        if self._connect_thread and self._connect_thread.is_alive():  # Prevent multiple connection threads [cite: 31]
            logging.warning("MQTT connection attempt already in progress.") # [cite: 31]
            return
        # Create and start a daemon thread for the blocking connection logic
        self._connect_thread = threading.Thread(target=self._connect_blocking, name="MQTTConnectThread", daemon=True)
        self._connect_thread.start() # [cite: 31, 32]

    def _connect_blocking(self):
        """
        Blocking MQTT connection logic with retries.
        This method is intended to be run in a separate thread.
        It will loop indefinitely, attempting to connect until successful or the script exits.
        """
        while True:  # Loop indefinitely until connected or script exits [cite: 32]
            if self.connected:  # If already connected (e.g., by a previous attempt in this loop)
                break # [cite: 32]
            try: # [cite: 33]
                logging.info(f"Attempting MQTT connection to {self.broker}:{self.port}...") # [cite: 33]
                if self.username and self.password:  # Set credentials if provided [cite: 33]
                    self.client.username_pw_set(self.username, self.password)

                # Setup Last Will and Testament (LWT)
                # This message is sent by the broker if the client disconnects ungracefully.
                lwt_payload = json.dumps({ # [cite: 34]
                    "status": "offline", "reason": "connection_lost", "mode": current_mode,
                    "presence_radar": ld2410c_presence_detected, "presence_camera": camera_detection,
                    "armed": system_armed, "override": manual_override_mode, "camera_blind": camera_blind # [cite: 34, 35]
                })
                self.client.will_set(MQTT_TOPIC_STATUS, payload=lwt_payload, qos=1, retain=True) # Set LWT [cite: 35]

                self.client.connect(self.broker, self.port, keepalive=60)  # Connect to broker (blocking call) [cite: 35]
                # Starts a background thread to handle MQTT network traffic (publish/subscribe acknowledgments, PINGREQ/PINGRESP)
                self.client.loop_start() # [cite: 35, 36]

                # Wait for the on_connect callback to confirm connection with a timeout
                connect_timeout_seconds = 10 # [cite: 36]
                connect_timeout = time.time() + connect_timeout_seconds
                while not self.connected and time.time() < connect_timeout: # [cite: 36, 37]
                    time.sleep(0.1)  # Check connection status periodically [cite: 37]

                if self.connected:  # Successfully connected (on_connect was called)
                    logging.info("MQTT connection established and network loop started.") # [cite: 37]
                    break  # Exit the retry loop [cite: 38]
                else:  # Timeout occurred before on_connect confirmed connection
                    logging.warning(f"MQTT connection attempt timed out after {connect_timeout_seconds}s. Stopping loop and retrying.") # [cite: 38, 39]
                    try:
                        self.client.loop_stop(force=True)  # Stop the network loop [cite: 39]
                        self.client.disconnect()  # Disconnect from the broker [cite: 39]
                    except: pass # Ignore errors during this cleanup attempt [cite: 39]
                    self.connected = False  # Ensure disconnected state [cite: 40]
                    mqtt_client_connected = False  # Update global flag [cite: 40]
            except ConnectionRefusedError:
                logging.error(f"MQTT connection refused by broker {self.broker}:{self.port}. Check broker, port, credentials, and firewall.") # [cite: 40]
            except OSError as e:  # Catches network errors like "Network is unreachable"
                logging.error(f"MQTT OS Error during connection: {e}") # [cite: 41]
            except Exception as e:  # Catch any other unexpected errors during connection
                logging.error(f"Unexpected MQTT connection error: {e}", exc_info=True) # [cite: 41]

            if not self.connected:  # If connection failed, wait before retrying
                retry_delay_seconds = 15 # [cite: 42]
                logging.info(f"Retrying MQTT connection in {retry_delay_seconds} seconds...") # [cite: 42]
                time.sleep(retry_delay_seconds) # [cite: 42]

    def disconnect(self):
        """
        Disconnects from the MQTT broker gracefully.
        Publishes a final "offline" status before disconnecting.
        """
        global mqtt_client_connected
        logging.info("Disconnecting MQTT client.") # [cite: 42, 43]
        if self.connected:  # Publish a final "offline" status if we were connected
            offline_status = {
                "status": "offline", "reason": "shutdown", "mode": current_mode,
                "presence_radar": ld2410c_presence_detected, "presence_camera": camera_detection,
                "armed": system_armed, "override": manual_override_mode, "camera_blind": camera_blind # [cite: 43, 44]
            }
            # Attempt to publish the offline status with QoS 1
            self.publish(MQTT_TOPIC_STATUS, offline_status, retain=True, qos=1) # [cite: 44]
            time.sleep(0.2)  # Give a brief moment for the message to be sent before disconnecting [cite: 44]
        try:
            if self.client.is_connected():  # Check if Paho client library thinks it's connected
                self.client.loop_stop()  # Stop the network processing thread gracefully [cite: 44, 45]
                self.client.disconnect()  # Send DISCONNECT packet to broker [cite: 45]
                logging.info("MQTT client disconnected from broker.") # [cite: 45]
            else:
                logging.info("MQTT client was already considered disconnected by Paho.") # [cite: 45]
        except Exception as e:
            logging.warning(f"Error during MQTT disconnect: {e}") # [cite: 45, 46]
        finally:  # Ensure flags are reset regardless of errors during disconnection
            self.connected = False # [cite: 46]
            mqtt_client_connected = False # [cite: 46]

    def publish(self, topic, payload, retain=False, qos=1):
        """
        Publishes a message to the MQTT broker.

        Args:
            topic (str): The MQTT topic to publish to.
            payload (dict, list, str, int, float, bool): The message payload.
                                                        Dicts/lists are JSON dumped.
            retain (bool, optional): Whether the message should be retained by the broker.
                                     Defaults to False.
            qos (int, optional): Quality of Service level (0, 1, or 2). Defaults to 1.

        Returns:
            bool: True if publish was successful (according to Paho), False otherwise.
        """
        if not self.connected:  # Don't attempt to publish if not connected
            logging.warning(f"MQTT publish failed (Client not connected): Topic={topic}") # [cite: 46, 47]
            return False # [cite: 47]
        try:
            # Ensure payload is a string (JSON dump if dict/list, convert otherwise)
            if isinstance(payload, dict) or isinstance(payload, list):
                payload_str = json.dumps(payload) # Serialize dict/list to JSON string
            elif isinstance(payload, (str, int, float, bool)): # Handle common primitive types [cite: 48]
                payload_str = str(payload) # Convert to string [cite: 48]
            else:
                logging.error(f"MQTT publish error: Unsupported payload type {type(payload)} for topic {topic}") # [cite: 48]
                return False # [cite: 48]

            # Publish the message using the Paho client
            result, mid = self.client.publish(topic, payload_str, qos=qos, retain=retain) # [cite: 49]

            if result == mqtt.MQTT_ERR_SUCCESS:  # Publish initiated successfully
                logging.debug(f"MQTT Message Published: Topic='{topic}', QoS={qos}, Retain={retain}, Payload='{payload_str}'") # [cite: 49]
                return True # [cite: 49]
            elif result == mqtt.MQTT_ERR_NO_CONN:  # Handle case where connection might have dropped since last check
                logging.warning(f"MQTT publish failed (MQTT_ERR_NO_CONN - No connection): Topic={topic}. Marking as disconnected.") # [cite: 50, 51]
                self._on_disconnect(self.client, None, result)  # Trigger disconnect logic, which may attempt reconnection [cite: 51]
                return False # [cite: 51]
            else:  # Other Paho MQTT errors
                logging.warning(f"MQTT publish failed with Paho error code {result}: {mqtt.error_string(result)} for topic {topic}") # [cite: 51]
                return False # [cite: 52]
        except Exception as e:  # Catch any other unexpected errors during publish
            logging.error(f"Error publishing MQTT message to topic {topic}: {e}", exc_info=True) # [cite: 52]
            return False # [cite: 52]

# --- LD2410C Serial Data Processing (UART) ---
def calculate_checksum(data_bytes):
    """
    Calculates the checksum for LD2410C data frames.
    The checksum is the sum of specified bytes, with only the lower 8 bits retained.

    Args:
        data_bytes (bytes): The bytes to be included in the checksum calculation.

    Returns:
        int: The calculated 8-bit checksum.
    """
    checksum = sum(data_bytes) # Sum of all byte values [cite: 52]
    return checksum & 0xFF  # Return only the lower 8 bits (modulo 256) [cite: 52]

def parse_ld2410c_frame(frame_data):
    """
    Parses a complete LD2410C data frame received from the serial port.
    This function specifically targets the "engineering mode" or "reporting data" frames
    that provide detailed target information.

    Args:
        frame_data (bytes): The raw byte data of a single LD2410C frame.

    Returns:
        dict: A dictionary containing parsed target data if successful,
              or None if parsing fails or the frame is not a recognized target report.
    """
    # [cite: 52, 53]
    # Validate frame start and end markers
    if not frame_data.startswith(FRAME_HEADER) or not frame_data.endswith(FRAME_END): # [cite: 54]
        logging.debug("Invalid LD2410C frame: incorrect start/end markers.") # [cite: 54]
        return None # [cite: 54]
    try:
        # Unpack frame length (2 bytes, little-endian unsigned short 'H')
        # and command word (1 byte, unsigned byte 'B').
        # These are located after the 4-byte header.
        length, command = struct.unpack('<HB', frame_data[4:7]) # [cite: 54]

        # Calculate expected total frame length:
        # 4 (header) + 2 (length field) + 1 (cmd field) + actual_data_payload_len + 1 (checksum byte) + 4 (footer)
        expected_total_len = len(FRAME_HEADER) + 2 + 1 + length + 1 + len(FRAME_END) # [cite: 55]
        if len(frame_data) != expected_total_len: # [cite: 55]
            logging.warning(f"LD2410C Frame length mismatch. Expected {expected_total_len}, got {len(frame_data)}") # [cite: 55]
            return None # [cite: 56]

        # Extract the actual data payload (its length is given by the 'length' field from the frame)
        payload_start_index = len(FRAME_HEADER) + 2 + 1 # Start of payload data [cite: 56]
        payload_end_index = payload_start_index + length # End of payload data [cite: 56]
        payload = frame_data[payload_start_index:payload_end_index] # [cite: 56]

        # Extract the checksum byte from the frame (it's located immediately after the payload)
        checksum_byte_from_frame = frame_data[payload_end_index] # [cite: 56, 57]

        # Data to be checksummed includes: length field (2 bytes), command field (1 byte), and the payload itself.
        data_to_checksum = frame_data[len(FRAME_HEADER) : payload_end_index] # Data from length field up to end of payload [cite: 57]
        calculated_checksum = calculate_checksum(data_to_checksum) # [cite: 57]

        if calculated_checksum != checksum_byte_from_frame: # [cite: 57]
            logging.warning(f"LD2410C Checksum mismatch. Expected {checksum_byte_from_frame:#04x}, calculated {calculated_checksum:#04x}") # [cite: 57, 58]
            return None # [cite: 58]

        # Process based on command word (0x01 is for reporting data from LD2410C in engineering/reporting mode)
        if command == 0x01:  # Engineering Mode / Reporting Data Command Word [cite: 58]
            # Check for target report identifier (0xAA as the first byte of the payload)
            # and ensure sufficient payload length for this specific report type.
            # Minimum length for this target report: 1 (type) + 2 (fixed header) + 5*2 (data values) = 13 bytes
            if length >= (1 + 2 + 2*5) and payload[0] == 0xAA:  # 0xAA indicates target report [cite: 58, 59]
                # Unpack target data based on LD2410C datasheet for reporting mode frames.
                # '<' denotes little-endian byte order.
                # B: unsigned char (1 byte), H: unsigned short (2 bytes).
                # Skipping payload[1] as it's a fixed header (often 0x00) for this report type according to some datasheets.
                target_state_code, mov_dist, mov_energy, stat_dist, stat_energy, detect_dist = struct.unpack( # [cite: 59, 60]
                    '<BHHHHH', payload[2:13]  # Unpack 11 bytes starting from payload byte 2 [cite: 60]
                ) # mov_dist: Moving Target Distance (cm), mov_energy: Moving Target Energy
                  # stat_dist: Static Target Distance (cm), stat_energy: Static Target Energy
                  # detect_dist: Overall Detection Distance (cm)

                target_states = {0: "None", 1: "Moving", 2: "Static", 3: "Moving+Static"} # Map state codes to strings [cite: 60]
                target_state_str = target_states.get(target_state_code, "Unknown") # Get string representation [cite: 61]

                # Construct a dictionary with the parsed data
                data = { # [cite: 61]
                    "timestamp": time.time(), "data_type": "target_report", # [cite: 61]
                    "target_state_code": target_state_code, "target_state": target_state_str, # [cite: 62]
                    # Report distance/energy only if the target state implies it (moving for moving, static for static)
                    "moving_target_distance_cm": mov_dist if target_state_code in [1, 3] else 0, # [cite: 62]
                    "moving_target_energy": mov_energy if target_state_code in [1, 3] else 0, # [cite: 62]
                    "static_target_distance_cm": stat_dist if target_state_code in [2, 3] else 0, # [cite: 62]
                    "static_target_energy": stat_energy if target_state_code in [2, 3] else 0, # [cite: 62, 63]
                    "detection_distance_cm": detect_dist,  # Overall detection distance reported by the sensor [cite: 63]
                }
                logging.debug(f"Parsed LD2410C Target Report Data: {data}") # [cite: 63]
                return data # [cite: 63, 64]
            else:
                logging.debug(f"LD2410C Command 0x01: Unknown payload type or insufficient length for target report. Payload[0]={payload[0] if length > 0 else 'N/A'}") # [cite: 64, 65]
        else:
            logging.debug(f"LD2410C: Unhandled command word: {command:#04x}") # [cite: 65]

        return None  # Return None if not a recognized/handled frame type or if an error occurred
    except struct.error as e:  # Error during struct.unpack
        logging.error(f"Error unpacking LD2410C frame data: {e}") # [cite: 65]
        return None # [cite: 65]
    except IndexError as e:  # Error if frame_data is too short for expected indexing operations
        logging.error(f"Error accessing LD2410C frame data (likely too short or malformed): {e}") # [cite: 66]
        return None # [cite: 66]
    except Exception as e:  # Catch-all for other unexpected errors during parsing
        logging.error(f"Unexpected error parsing LD2410C frame: {e}", exc_info=True) # [cite: 66]
        return None # [cite: 66]

def serial_reader_thread_func():
    """
    Thread function dedicated to continuously reading data from the LD2410C's serial port (UART),
    buffering the data, identifying complete frames, and parsing them.
    Parsed data is then published via MQTT.
    """
    global serial_port_instance, serial_thread_running # Use global instances/flags
    logging.info("LD2410C Serial reader thread started.") # [cite: 66, 67]
    read_buffer = b''  # Buffer to accumulate incoming serial data [cite: 67]

    while serial_thread_running: # Loop as long as the thread is supposed to be running [cite: 67]
        try:
            if serial_port_instance and serial_port_instance.is_open: # Check if serial port is valid and open
                bytes_waiting = serial_port_instance.in_waiting  # Check how many bytes are available to read [cite: 67]
                if bytes_waiting > 0:
                    read_buffer += serial_port_instance.read(bytes_waiting)  # Read all available bytes into the buffer [cite: 67, 68]

                # Process the buffer to find and parse complete frames
                # Loop as long as a potential frame start (FRAME_HEADER) and
                # a subsequent frame end (FRAME_END) can be found in the buffer.
                while True: # [cite: 69]
                    try:
                        start_index = read_buffer.index(FRAME_HEADER) # Find the start of a frame [cite: 69]
                        # Find the end marker *after* the found start marker to ensure correct frame boundary
                        end_index = read_buffer.index(FRAME_END, start_index + len(FRAME_HEADER)) # [cite: 69, 70]
                    except ValueError:  # If FRAME_HEADER or FRAME_END is not found
                        # Heuristic: If a header was found but not an end, and the buffer is getting excessively large,
                        # it might indicate corrupted data or a very long delay. Trim old data to prevent unbounded growth.
                        if FRAME_HEADER in read_buffer and len(read_buffer) > 1024: # Arbitrary large size [cite: 70, 71]
                             corrupted_start = read_buffer.find(FRAME_HEADER) # Find first occurrence of header
                             if corrupted_start > 256 : # If significant data before a possible (potentially new) header [cite: 71]
                                 logging.warning(f"Trimming serial buffer due to missing end marker and large size. Buffer size: {len(read_buffer)}") # [cite: 71, 72, 73]
                                 read_buffer = read_buffer[corrupted_start:]  # Keep data from the potential (next) header onwards [cite: 73]
                        break  # Exit this inner loop, wait for more data to arrive

                    frame_end_pos = end_index + len(FRAME_END) # Calculate the exact end position of the frame in the buffer
                    frame = read_buffer[start_index:frame_end_pos]  # Extract the potential complete frame [cite: 74]

                    # Before removing the processed part from the buffer, check if this was the *first* occurrence of the header.
                    # If start_index > 0, it means there was some garbage data before this valid frame.
                    if start_index > 0: # [cite: 74, 75]
                        logging.debug(f"Discarding {start_index} bytes of garbage data from serial buffer before frame.") # [cite: 75]

                    # Remove the processed frame (and any preceding garbage data) from the buffer
                    read_buffer = read_buffer[frame_end_pos:] # [cite: 76]

                    # Parse the extracted frame
                    parsed_data = parse_ld2410c_frame(frame) # [cite: 76]
                    if parsed_data: # If parsing was successful and yielded data
                        publish_ld2410c_details(parsed_data)  # Publish the detailed sensor data via MQTT [cite: 76, 77]
            else:  # Serial port not open or not initialized
                logging.debug("LD2410C Serial port not open in reader thread, sleeping.") # [cite: 77]
                time.sleep(5) # Wait before checking again [cite: 77]

            time.sleep(0.02)  # Brief sleep to yield CPU and prevent busy-waiting. Adjust as needed. [cite: 77, 78]
        except serial.SerialException as e: # Handle serial port specific errors (e.g., device disconnected)
            logging.error(f"LD2410C Serial error in reader thread: {e}. Closing port and attempting reopen.") # [cite: 78, 79]
            if serial_port_instance and serial_port_instance.is_open: # [cite: 79]
                try: serial_port_instance.close() # Attempt to close the port [cite: 79]
                except: pass # Ignore errors during close
            time.sleep(10)  # Wait before attempting to reopen [cite: 79]
            try:
                # Attempt to re-initialize and reopen the serial port
                serial_port_instance = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1) # Use non-blocking timeout [cite: 80]
                logging.info(f"LD2410C Serial port {SERIAL_PORT} reopened successfully after error.") # [cite: 80]
            except Exception as reopen_e:
                logging.error(f"Failed to reopen LD2410C serial port {SERIAL_PORT} after error: {reopen_e}") # [cite: 80]
                serial_port_instance = None  # Mark as None so main init might try again if script is restarted globally [cite: 81]
                time.sleep(10)  # Wait longer if reopen fails before trying again in the loop [cite: 81]
        except Exception as e:  # Catch any other unhandled exceptions in this thread
            logging.critical(f"Unhandled exception in LD2410C serial reader thread: {e}", exc_info=True) # [cite: 81]
            time.sleep(10)  # Wait before continuing after a critical error in the thread [cite: 81, 82]

    logging.info("LD2410C Serial reader thread finished.") # [cite: 82]
    # Ensure port is closed when thread exits (e.g., on script shutdown when serial_thread_running is False)
    if serial_port_instance and serial_port_instance.is_open: # [cite: 82]
        try: serial_port_instance.close() # [cite: 82]
        except: pass # [cite: 82]

def publish_ld2410c_details(details_payload):
    """
    Publishes the detailed LD2410C sensor data (parsed from serial/UART) to MQTT.

    Args:
        details_payload (dict): The dictionary containing parsed LD2410C sensor data.
    """
    global mqtt_client_instance # Use the global MQTT client instance
    if mqtt_client_instance and mqtt_client_connected:  # Check if MQTT client is initialized and connected
        logging.debug(f"Publishing LD2410C detailed data: {details_payload}") # [cite: 82, 83]
        # Use QoS 0 for high-frequency, non-critical sensor data to reduce overhead and latency.
        # Retain is False as this is real-time data.
        mqtt_client_instance.publish(MQTT_TOPIC_LD2410C_DETAILS, details_payload, retain=False, qos=0) # [cite: 83]
    else:
        logging.warning("Cannot publish LD2410C details: MQTT client not connected or not initialized.") # [cite: 83]

# --- Mode Management Logic ---
def determine_target_mode():
    """
    Determines the desired system operational mode (PROACTIVE or STANDBY)
    based on the current manual override setting and the radar sensor state.
    Manual override takes precedence over automatic mode determination.

    Returns:
        str: The target operational mode ("PROACTIVE" or "STANDBY").
    """
    # [cite: 83]
    global manual_override_mode, ld2410c_presence_detected # Use global state variables
    if manual_override_mode:  # If a manual override mode is set, it takes precedence
        return manual_override_mode # [cite: 84]
    else:  # Otherwise, determine mode automatically based on radar presence
        return "PROACTIVE" if ld2410c_presence_detected else "STANDBY" # [cite: 84]

def switch_mode(new_mode):
    """
    Handles the transition between PROACTIVE and STANDBY operational modes.
    This includes setting the CPU governor for power management and controlling
    Frigate's detection and recording states via MQTT.

    Args:
        new_mode (str): The new operational mode to switch to ("PROACTIVE" or "STANDBY").
    """
    # [cite: 84, 85]
    global current_mode, mqtt_client_instance, mqtt_client_connected # Use global variables
    if new_mode == current_mode:  # No change needed if the new mode is the same as the current one
        return # [cite: 85]
    logging.info(f"Switching System Mode from '{current_mode}' to '{new_mode}'") # [cite: 85]
    current_mode = new_mode # Update the global current_mode state [cite: 85]

    # Determine Frigate payload and CPU governor based on the new mode
    frigate_payload_to_send = FRIGATE_CONTROL_PAYLOAD_ON if new_mode == "PROACTIVE" else FRIGATE_CONTROL_PAYLOAD_OFF # [cite: 85]
    governor_to_set = CPU_GOVERNOR_PROACTIVE if new_mode == "PROACTIVE" else CPU_GOVERNOR_STANDBY # [cite: 85]

    set_cpu_governor(governor_to_set)  # Set the CPU governor accordingly [cite: 85, 86]

    # Control Frigate's detection and recording state via MQTT if the client is connected
    if mqtt_client_instance and mqtt_client_connected: # [cite: 86]
        mqtt_client_instance.publish(FRIGATE_TOPIC_DETECT_SET, frigate_payload_to_send, qos=1) # Control detection
        mqtt_client_instance.publish(FRIGATE_TOPIC_RECORD_SET, frigate_payload_to_send, qos=1) # Control recording
        logging.info(f"Sent '{frigate_payload_to_send}' to Frigate detection and recording topics for camera '{FRIGATE_CAMERA_NAME}'.") # [cite: 86]
    else:
        logging.warning(f"Cannot control Frigate (target mode: {new_mode}): MQTT client not ready.") # [cite: 86]

    publish_status()  # Publish the updated system status immediately after a mode change [cite: 86, 87]

# --- Status Publishing ---
def publish_status():
    """
    Publishes the current comprehensive system status to the MQTT_TOPIC_STATUS.
    This includes operational mode, sensor states, armed status, override status, and camera blind status.
    The message is published with QoS 1 and retained by the broker.
    """
    global last_status_publish_time, current_mode, manual_override_mode, system_armed
    global mqtt_client_instance, ld2410c_presence_detected, camera_detection, camera_blind

    status_payload = { # [cite: 87]
        "timestamp": time.time(),  # Current Unix timestamp
        "mode": current_mode,  # Current operational mode (PROACTIVE or STANDBY)
        "presence_radar": ld2410c_presence_detected,  # Boolean: Radar (LD2410C GPIO) presence
        "presence_camera": camera_detection,  # Boolean: Camera (Frigate 'person' detection) presence [cite: 87, 88]
        "armed": system_armed,  # Boolean: System armed state
        "override": manual_override_mode,  # String (mode name) or None: Manual override mode
        "status": "online",  # General online status of this script/node
        "camera_blind": camera_blind  # Boolean: Suspected camera tamper/blind state [cite: 88]
    }
    if mqtt_client_instance and mqtt_client_connected:  # Ensure MQTT client is available and connected
        if mqtt_client_instance.publish(MQTT_TOPIC_STATUS, status_payload, retain=True, qos=1):  # Publish with retain=True [cite: 88]
            last_status_publish_time = time.monotonic()  # Update time of last successful publish using monotonic clock for interval checks [cite: 89]
            logging.debug(f"Published system status: {status_payload}") # [cite: 89]
    else:
        logging.warning("Cannot publish system status: MQTT client not connected or not initialized.") # [cite: 89]

def publish_ld2410c_status():
    """
    Publishes the basic LD2410C radar presence status (derived from the GPIO OUT pin)
    to the MQTT_TOPIC_LD2410C_STATUS.
    The message is published with QoS 1 and retained.
    """
    global mqtt_client_instance, ld2410c_presence_detected # Use global variables
    status_payload = {"timestamp": time.time(), "presence": ld2410c_presence_detected} # Simple status payload
    if mqtt_client_instance and mqtt_client_connected:  # Ensure MQTT client is available and connected [cite: 89]
        logging.debug(f"Publishing LD2410C OUT pin status (GPIO based): {status_payload}") # [cite: 90]
        mqtt_client_instance.publish(MQTT_TOPIC_LD2410C_STATUS, status_payload, retain=True, qos=1)  # Publish with retain=True [cite: 90]
    else:
        logging.warning("Cannot publish LD2410C OUT pin status: MQTT client not connected or not initialized.") # [cite: 90]

# --- Command Handling (from Node-RED via MQTT) ---
def handle_node_red_command(command_data):
    """
    Processes commands received from an external controller (e.g., Node-RED) via MQTT.
    Supported commands include setting manual override mode and arming/disarming the system.

    Args:
        command_data (dict): The parsed JSON data from the MQTT command message.
    """
    global manual_override_mode, system_armed # Modify global state based on commands
    logging.info(f"Processing Node-RED Command: {command_data}") # [cite: 90]
    needs_status_update = False  # Flag to publish status only if a relevant state changed [cite: 90, 91]
    try:
        if 'override_mode' in command_data:  # Handle override mode commands [cite: 91]
            override_cmd = command_data['override_mode'].upper()  # Normalize to uppercase for case-insensitive comparison [cite: 91]
            if override_cmd in ["PROACTIVE", "STANDBY"]:  # Valid override modes
                if manual_override_mode != override_cmd:  # Check if it's a new override state
                    manual_override_mode = override_cmd # [cite: 91, 92]
                    needs_status_update = True # [cite: 92]
                    logging.info(f"Manual override mode set to: '{manual_override_mode}' by command.") # [cite: 92]
            elif override_cmd in ["AUTO", "NONE", "SCHEDULE"]:  # Commands to clear/reset manual override
                if manual_override_mode is not None:  # Check if there was an override to clear [cite: 92, 93]
                    manual_override_mode = None # [cite: 93]
                    needs_status_update = True # [cite: 93]
                    logging.info("Manual override cleared by command.") # [cite: 93]
            else:
                logging.warning(f"Received unknown 'override_mode' command value: {override_cmd}") # [cite: 93, 94]

        elif 'mode' in command_data:  # Handle ARM/DISARM commands (using 'mode' key for this example) [cite: 94]
            mode_cmd = command_data['mode'].upper()  # Normalize to uppercase [cite: 94]
            if mode_cmd == "ARMED": # Command to arm the system
                if not system_armed:  # Check if it's a new state (was previously disarmed)
                    system_armed = True # [cite: 94, 95]
                    needs_status_update = True # [cite: 95]
                    logging.info("System ARMED by command.") # [cite: 95]
            elif mode_cmd == "DISARMED": # Command to disarm the system
                if system_armed:  # Check if it's a new state (was previously armed) [cite: 95, 96]
                    system_armed = False # [cite: 96]
                    needs_status_update = True # [cite: 96]
                    logging.info("System DISARMED by command.") # [cite: 96]
            else:
                logging.warning(f"Received unknown 'mode' (for arm/disarm) command value: {mode_cmd}") # [cite: 96, 97]

        else:  # Unrecognized command structure
            logging.warning(f"Received unrecognized command structure from Node-RED: {command_data}") # [cite: 97]

        if needs_status_update:  # If any relevant state was changed by the command
            publish_status()  # Publish the updated system status immediately [cite: 97]

    except Exception as e:  # Catch any errors during command processing
        logging.error(f"Error processing Node-RED command ({command_data}): {e}", exc_info=True) # [cite: 97, 98]

# --- Sensor Fusion and Tamper Detection Logic ---
def update_camera_blind_status():
    """
    Updates the `camera_blind` global status.
    This function implements logic to suspect camera tampering or obstruction if:
    1. The radar (LD2410C) is actively detecting presence.
    2. The camera (Frigate) has not detected a 'person' for a defined timeout period
       (NO_DETECTION_WHILE_RADAR_TIMEOUT) despite ongoing radar activity.

    This function should be called periodically, especially when the radar is active.
    If the `camera_blind` status changes, it triggers a system status publish.
    """
    # [cite: 98, 99]
    global camera_blind, ld2410c_presence_detected, camera_detection
    global last_camera_detection_time_with_radar, time_radar_became_active, NO_DETECTION_WHILE_RADAR_TIMEOUT # [cite: 100]
    now = time.time() # Current time

    new_camera_blind_state = False  # Assume not blind by default for this check iteration

    if ld2410c_presence_detected:  # Only consider camera blind if radar is currently active [cite: 100]
        if not camera_detection:  # And camera currently detects no person [cite: 100]
            # Scenario 1: There was a previous camera detection *while radar was also active*,
            # but it's been too long since that last correlated detection.
            if last_camera_detection_time_with_radar > 0: # A camera detection occurred at some point during current/previous radar active phase [cite: 100, 101]
                if (now - last_camera_detection_time_with_radar) > NO_DETECTION_WHILE_RADAR_TIMEOUT: # [cite: 101]
                    new_camera_blind_state = True # Mark as potentially blind
            # Scenario 2: Radar has been active for the timeout duration,
            # AND there have been NO camera detections at all during this current radar active period.
            # `time_radar_became_active` is set when radar transitions from False to True.
            # `last_camera_detection_time_with_radar` would be 0 if no camera detection has occurred yet
            # in this specific radar active period.
            elif time_radar_became_active > 0 and last_camera_detection_time_with_radar == 0: # Radar active, but no camera detection seen *with* radar yet [cite: 102, 103, 104]
                if (now - time_radar_became_active) > NO_DETECTION_WHILE_RADAR_TIMEOUT: # If radar has been active for timeout duration [cite: 104]
                    new_camera_blind_state = True # Mark as potentially blind

    # If radar is not active, camera cannot be considered "blind" by this specific logic,
    # so `new_camera_blind_state` remains False (or becomes False if it was True and radar just stopped).
    # This logic is handled when radar state changes to False in the main loop.

    if new_camera_blind_state != camera_blind:  # If the calculated blind state has changed from the global state [cite: 105]
        camera_blind = new_camera_blind_state  # Update the global state [cite: 105]
        if camera_blind: # Log the change
            logging.warning("CAMERA BLIND state: True (Radar active, no camera person detection for timeout).") # [cite: 105]
        else:
            logging.info("CAMERA BLIND state: False (Condition resolved or not met).") # [cite: 105]
        publish_status()  # Publish status update because camera_blind state changed [cite: 105, 106]

def check_fusion_logic():
    """
    Checks for a 'Hidden Intruder' (sensor fusion) condition.
    This condition is met if:
    - The system is ARMED.
    - The radar (LD2410C) detects presence.
    - The camera (Frigate) does NOT detect a 'person'.
    If the condition is met and the alert cooldown period has passed,
    a "hidden_intruder" alert is logged and published via MQTT.
    """
    global last_fusion_alert_time, ld2410c_presence_detected, camera_detection
    global mqtt_client_instance, system_armed # Use global variables
    now = time.time() # Current time

    # Condition for Hidden Intruder: System is armed, radar detects presence, AND camera does NOT detect a person
    if system_armed and ld2410c_presence_detected and not camera_detection: # [cite: 106]
        if (now - last_fusion_alert_time) > ALERT_COOLDOWN:  # Check if alert cooldown period has passed [cite: 106]
            alert_message = "Hidden intruder detected! Radar presence without camera confirmation." # [cite: 107, 108]
            log_alert_event(alert_message, level=logging.WARNING)  # Log to dedicated fusion_alerts.log (or main if fallback) [cite: 108]

            if mqtt_client_instance and mqtt_client_connected: # If MQTT is available
                # Publish a structured JSON alert for easier parsing by other systems (e.g., Node-RED)
                alert_payload = { # [cite: 108]
                    "type": "hidden_intruder", # Type of alert [cite: 109]
                    "message": alert_message, # Alert message [cite: 109]
                    "node": MQTT_CLIENT_ID,  # Identify which SRM node generated the alert [cite: 109]
                    "timestamp": now # Timestamp of the alert [cite: 109]
                }
                mqtt_client_instance.publish(MQTT_TOPIC_ALERTS, json.dumps(alert_payload), qos=1) # Publish alert [cite: 110]
            last_fusion_alert_time = now  # Reset cooldown timer for this specific alert type [cite: 110]

def check_tamper_detection():
    """
    Checks for a 'Camera Tamper Suspected' condition.
    This condition is met if:
    - The system is ARMED.
    - The radar (LD2410C) detects presence.
    - The camera is currently considered 'blind' (as determined by `update_camera_blind_status`).
    If the condition is met and the alert cooldown period has passed,
    a "tamper_suspected" alert is logged and published via MQTT.
    """
    # [cite: 110, 111]
    global last_tamper_alert_time, ld2410c_presence_detected, camera_blind
    global mqtt_client_instance, system_armed # Use global variables [cite: 111, 112]
    now = time.time() # Current time

    # The `camera_blind` status is updated by `update_camera_blind_status()` in the main loop.
    # Condition for Tamper: System is armed, radar detects presence, AND camera is marked as blind.
    if system_armed and ld2410c_presence_detected and camera_blind: # [cite: 112]
        if (now - last_tamper_alert_time) > ALERT_COOLDOWN:  # Check if alert cooldown period has passed [cite: 112]
            alert_message = "Tamper suspected: Camera may be obscured or malfunctioning (radar active, camera blind)." # [cite: 112, 113]
            log_alert_event(alert_message, level=logging.WARNING)  # Log to dedicated fusion_alerts.log (or main) [cite: 113]

            if mqtt_client_instance and mqtt_client_connected: # If MQTT is available
                # Publish a structured JSON alert
                alert_payload = { # [cite: 113]
                    "type": "tamper_suspected", # Type of alert [cite: 114]
                    "message": alert_message, # Alert message [cite: 114]
                    "node": MQTT_CLIENT_ID,  # Identify which SRM node [cite: 114]
                    "timestamp": now # Timestamp of the alert [cite: 114]
                }
                mqtt_client_instance.publish(MQTT_TOPIC_ALERTS, json.dumps(alert_payload), qos=1) # Publish alert [cite: 114, 115]
            last_tamper_alert_time = now  # Reset cooldown timer for this specific alert type [cite: 115]

# --- Main Operational Loop ---
def main_loop():
    """
    The main operational loop of the mode manager.
    This loop continuously:
    1. Checks the LD2410C radar sensor state (via GPIO).
    2. Determines the target system operational mode (PROACTIVE/STANDBY).
    3. Switches the mode if necessary.
    4. Updates the camera blind status.
    5. Runs sensor fusion and tamper detection logic (if armed).
    6. Periodically publishes the system status.
    """
    # [cite: 115]
    global last_status_publish_time, current_mode, ld2410c_presence_detected
    global time_radar_became_active, last_camera_detection_time_with_radar # For tamper logic [cite: 116, 117]

    logging.info("Starting Mode Manager Main Loop...") # [cite: 117]
    previous_radar_state = ld2410c_presence_detected  # Initialize with current (likely False) state [cite: 117]

    while True: # Loop indefinitely until KeyboardInterrupt or critical error
        try:
            now_monotonic = time.monotonic()  # Use monotonic time for interval checks (not affected by system clock changes)

            # 1. Check LD2410C OUT Pin Sensor State (Radar Presence)
            current_gpio_pin_value = GPIO.input(LD2410C_OUT_PIN) # Read GPIO pin state [cite: 118]
            current_radar_state = (current_gpio_pin_value == GPIO.HIGH) # HIGH means presence detected [cite: 118]

            if current_radar_state != previous_radar_state:  # If radar state has changed
                logging.info(f"LD2410C OUT Pin Presence (Radar) Changed: {previous_radar_state} -> {current_radar_state}") # [cite: 118]
                ld2410c_presence_detected = current_radar_state  # Update global radar state [cite: 118, 119]
                publish_ld2410c_status()  # Publish basic radar status (GPIO based) immediately on change [cite: 119]

                if ld2410c_presence_detected:  # Radar just transitioned from False to True (presence started)
                    time_radar_became_active = time.time()  # Record the timestamp when this radar active period started [cite: 119]
                    # Reset this timestamp as a new radar active period has begun.
                    # Any camera detections from now on (while this radar is active) will update it.
                    last_camera_detection_time_with_radar = 0 # [cite: 120, 121, 122]
                else:  # Radar just transitioned from True to False (presence ended)
                    time_radar_became_active = 0  # Reset the timestamp for radar active period start [cite: 122]
                    # If radar becomes inactive, the `camera_blind` condition (which depends on radar being active
                    # and no camera detection for a timeout) should be re-evaluated and likely cleared.
                    if camera_blind: # If it was previously considered blind [cite: 123, 124]
                        update_camera_blind_status()  # This will re-evaluate; since radar is now false, it should set camera_blind to False and publish status [cite: 124]

                previous_radar_state = current_radar_state  # Update state for the next iteration [cite: 124]
                publish_status()  # Publish full system status on any radar state change [cite: 124, 125]

            # 2. Determine Target System Mode (PROACTIVE/STANDBY) based on current radar state and manual override
            target_operational_mode = determine_target_mode() # [cite: 125]

            # 3. Switch Operational Mode if Necessary
            if target_operational_mode != current_mode: # If the determined target mode is different from the current mode
                switch_mode(target_operational_mode)  # This function also calls publish_status() internally [cite: 125, 126]

            # 4. Update Camera Blind Status
            # This function checks conditions and updates the global `camera_blind` variable.
            # It will also call publish_status() if the `camera_blind` state changes.
            # It's most relevant to check this when radar is active.
            if ld2410c_presence_detected:  # Only actively check for blindness if radar is currently on [cite: 126, 127, 128]
                update_camera_blind_status() # [cite: 128]

            # 5. Run Sensor Fusion and Tamper Detection Logic if the system is ARMED
            if system_armed: # Only perform these checks if the system is armed
                check_fusion_logic()      # Checks for hidden intruders (radar without camera)
                check_tamper_detection()  # Checks for camera tampering (radar with camera blind) [cite: 128, 129]

            # 6. Periodic System Status Update
            # Publish the full system status at regular intervals (STATUS_PUBLISH_INTERVAL)
            # This ensures the status is fresh even if no other events trigger a publish.
            if mqtt_client_connected and (now_monotonic - last_status_publish_time >= STATUS_PUBLISH_INTERVAL): # [cite: 129]
                # This check is a bit simplified; a more robust way might involve a "dirty" flag
                # to avoid publishing if a status-changing event (mode switch, radar change, camera_blind change)
                # has *just* published the status. However, for now, this ensures periodic updates.
                if target_operational_mode == current_mode: # Only publish if mode hasn't just changed (which would have already published) [cite: 130, 131]
                    publish_status() # [cite: 131]

            time.sleep(1)  # Main loop runs approximately every 1 second. Adjust for desired responsiveness vs CPU load.
        except KeyboardInterrupt:  # Allow graceful exit with Ctrl+C
            logging.info("KeyboardInterrupt received. Exiting main loop...") # [cite: 131]
            break # Exit the while loop [cite: 131, 132]
        except Exception as e:  # Catch any other unhandled exceptions in the main loop
            logging.critical(f"Unhandled exception in main loop: {e}", exc_info=True) # [cite: 132]
            # Potentially add more specific error handling or recovery logic here if needed.
            time.sleep(10)  # Wait a bit before trying to continue, in case of temporary issues [cite: 132]

# --- Cleanup Function ---
def cleanup():
    """
    Cleans up resources (GPIO, MQTT client, serial thread) before the script exits.
    This function is intended to be called during shutdown (e.g., via a finally block or signal handler).
    """
    # [cite: 132, 133]
    global serial_thread_running, serial_thread, serial_port_instance, mqtt_client_instance # Access global variables
    logging.info("--- Mode Manager Shutting Down ---") # [cite: 133]

    # Stop serial reader thread if it's running and enabled
    if serial_thread and serial_thread.is_alive(): # Check if thread object exists and is alive [cite: 133]
        logging.info("Stopping LD2410C serial reader thread...") # [cite: 133]
        serial_thread_running = False  # Signal the thread's loop to stop [cite: 133]
        serial_thread.join(timeout=2.0)  # Wait for the thread to finish (with a 2-second timeout) [cite: 133]
        if serial_thread.is_alive(): # If thread is still alive after timeout [cite: 133, 134]
            logging.warning("LD2410C Serial reader thread did not stop gracefully within timeout.") # [cite: 134]
        else:
            logging.info("LD2410C Serial reader thread stopped.") # [cite: 134]

    # Close serial port if it was opened
    if serial_port_instance and serial_port_instance.is_open: # Check if port object exists and is open [cite: 134]
        try:
            serial_port_instance.close() # Close the serial port
            logging.info(f"Serial port {SERIAL_PORT} for LD2410C closed.") # [cite: 134, 135]
        except Exception as e:
            logging.warning(f"Error closing LD2410C serial port: {e}") # [cite: 135]

    # Disconnect MQTT client gracefully
    if mqtt_client_instance: # Check if MQTT client instance exists [cite: 135]
        mqtt_client_instance.disconnect()  # This method handles publishing LWT and graceful disconnect [cite: 135]

    # Clean up GPIO resources
    try:
        GPIO.cleanup() # Release GPIO resources used by this script
        logging.info("GPIO cleanup done.") # [cite: 135, 136]
    except Exception as e:
        logging.warning(f"Error during GPIO cleanup: {e}") # [cite: 136]

    logging.info("--- Cleanup Complete ---") # [cite: 136]

# --- Main Execution Block ---
if __name__ == "__main__":
    # This block executes when the script is run directly.
    logging.info(f"====== OASIS LD2410C Serial Mode Manager Starting Up (ID: {MQTT_CLIENT_ID}) ======") # [cite: 136]
    setup_fusion_logger()  # Initialize the dedicated logger for fusion/tamper alerts [cite: 136]

    # Initialize Serial Port for LD2410C detailed data (if enabled in config)
    if ENABLE_SERIAL_DEBUG: # [cite: 136]
        try:
            # Attempt to open the serial port with a non-blocking read timeout (0.1s)
            serial_port_instance = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1) # [cite: 137]
            logging.info(f"Opened serial port {SERIAL_PORT} at {BAUD_RATE} baud for LD2410C detailed data.") # [cite: 137]
            serial_thread_running = True # Set flag to allow serial reader thread to run
            # Create and start the daemon thread for reading serial data
            serial_thread = threading.Thread(target=serial_reader_thread_func, name="LD2410CSerialReaderThread", daemon=True)
            serial_thread.start()  # Start the thread to read serial data in the background [cite: 137]
        except serial.SerialException as e:  # Handle errors specifically related to opening the serial port
            logging.error(f"Failed to open serial port {SERIAL_PORT} for LD2410C: {e}. Detailed radar data will be unavailable.") # [cite: 138, 139]
            serial_port_instance = None  # Ensure it's None if opening failed, so other parts of code don't try to use it [cite: 139]
        except Exception as e:  # Catch any other unexpected errors during serial initialization
            logging.error(f"Unexpected error opening serial port {SERIAL_PORT} for LD2410C: {e}. Detailed radar data will be unavailable.", exc_info=True) # [cite: 139]
            serial_port_instance = None # [cite: 139]

    # Initialize and connect MQTT Client
    mqtt_client_instance = MQTTClientWrapper( # Create an instance of the MQTT wrapper [cite: 140]
        MQTT_BROKER, MQTT_PORT, MQTT_CLIENT_ID,
        MQTT_USERNAME, MQTT_PASSWORD,
        handle_node_red_command  # Pass the command handler function
    )
    mqtt_client_instance.connect_async()  # Connect to MQTT broker asynchronously in a separate thread [cite: 140]

    # Wait for initial MQTT connection with a timeout before starting the main loop
    # This gives the MQTT client a chance to establish connection first.
    logging.info("Waiting for initial MQTT connection...") # [cite: 140]
    connection_wait_timeout_seconds = 20 # Define a timeout for waiting [cite: 140]
    connection_wait_start = time.time() # Record start time
    while not mqtt_client_connected and (time.time() - connection_wait_start < connection_wait_timeout_seconds): # Loop until connected or timeout [cite: 140]
        time.sleep(0.5)  # Check periodically [cite: 140, 141]

    if not mqtt_client_connected: # If connection was not established within the timeout [cite: 141]
        logging.warning(f"MQTT did not connect within {connection_wait_timeout_seconds}s timeout. Proceeding; script will keep trying to connect in the background.") # [cite: 141, 142]
    else: # If connection was successful
        logging.info("MQTT connection established.") # [cite: 142]
        # Publish initial full system status and radar GPIO status once MQTT is confirmed connected
        publish_status() # [cite: 142]
        publish_ld2410c_status() # [cite: 142]

    # Run the main operational loop with a try/finally block
    # This ensures that the cleanup() function is called when the main_loop exits
    # (either normally, via KeyboardInterrupt, or due to an unhandled exception).
    try:
        main_loop() # Start the main logic of the application
    finally:
        cleanup()  # Perform cleanup actions (GPIO, MQTT, threads) before exiting [cite: 142, 143]

    logging.info(f"====== OASIS LD2410C Serial Mode Manager (ID: {MQTT_CLIENT_ID}) Shutdown Complete ======") # [cite: 143]
