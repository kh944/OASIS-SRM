# integration_test_srm.py
import paho.mqtt.client as mqtt
import time
import json
import sys
from queue import Queue, Empty
import threading

# --- Configuration ---
BROKER_ADDRESS = "localhost" # Address of the MQTT broker (running on the Pi)
BROKER_PORT = 1883
CLIENT_ID = "SRM_Integration_Tester"

# Topics to interact with
CMD_TOPIC = "oasis/security/commands"
STATUS_TOPIC = "oasis/security/status"
RADAR_STATUS_TOPIC = "oasis/sensor/ld2410c/status"
ALERT_TOPIC = "oasis/srm/alerts"

# Queue to store received messages
message_queue = Queue()
# Lock for printing safely from multiple threads if needed
print_lock = threading.Lock()

# --- MQTT Client Setup ---
def on_connect(client, userdata, flags, rc, properties=None):
    """Callback when connected to MQTT broker."""
    with print_lock:
        if rc == 0:
            print(f"Tester Connected to MQTT Broker: {BROKER_ADDRESS}")
            # Subscribe to topics we want to monitor
            client.subscribe(STATUS_TOPIC)
            print(f"Tester Subscribed to: {STATUS_TOPIC}")
            client.subscribe(RADAR_STATUS_TOPIC)
            print(f"Tester Subscribed to: {RADAR_STATUS_TOPIC}")
            client.subscribe(ALERT_TOPIC)
            print(f"Tester Subscribed to: {ALERT_TOPIC}")
        else:
            print(f"Tester Failed to connect, return code {rc}")
            sys.exit(1) # Exit if connection fails

def on_message(client, userdata, msg):
    """Callback when a message is received."""
    try:
        payload_str = msg.payload.decode('utf-8')
        # Store topic and payload in queue for processing
        message_queue.put({'topic': msg.topic, 'payload_str': payload_str})
    except Exception as e:
        with print_lock:
            print(f"Error processing message on {msg.topic}: {e}")

def setup_mqtt_client():
    """Creates and configures the MQTT client."""
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=CLIENT_ID)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(BROKER_ADDRESS, BROKER_PORT, 60)
    except Exception as e:
        print(f"Failed to connect tester to MQTT broker at {BROKER_ADDRESS}:{BROKER_PORT}. Error: {e}")
        print("Ensure the broker is running and accessible.")
        sys.exit(1)
    return client

# --- Helper Functions ---
def clear_message_queue():
    """Empties the message queue."""
    while not message_queue.empty():
        try:
            message_queue.get_nowait()
        except Empty:
            break

def wait_for_message_on_topic(topic, timeout=10):
    """Waits for the next message on a specific topic."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            msg_data = message_queue.get(timeout=0.2)
            if msg_data['topic'] == topic:
                try:
                    return json.loads(msg_data['payload_str'])
                except json.JSONDecodeError:
                     with print_lock:
                        print(f"Warning: Received non-JSON payload on {topic}: {msg_data['payload_str']}")
                     return msg_data['payload_str'] # Return raw string if not JSON
            else:
                # Put back message if it's not the one we're looking for
                message_queue.put(msg_data)
                time.sleep(0.05) # Small sleep to prevent busy-waiting
        except Empty:
            time.sleep(0.1) # Wait longer if queue is empty
    return None # Timeout

def check_status(expected_state, timeout=5):
    """Waits for a status message and checks specific key-value pairs."""
    print(f"  Waiting for status update (expecting {expected_state})...")
    payload = wait_for_message_on_topic(STATUS_TOPIC, timeout)
    if payload is None:
        print(f"  FAIL: Timed out waiting for status message on {STATUS_TOPIC}")
        return False
    if not isinstance(payload, dict):
        print(f"  FAIL: Received non-dictionary payload on {STATUS_TOPIC}: {payload}")
        return False

    match = True
    for key, expected_value in expected_state.items():
        if key not in payload:
            print(f"  FAIL: Key '{key}' not found in status payload.")
            match = False
        elif payload[key] != expected_value:
            print(f"  FAIL: Key '{key}' has value '{payload[key]}', expected '{expected_value}'.")
            match = False

    if match:
        print(f"  PASS: Received expected status: {expected_state}")
        return True
    else:
        print(f"  Full received payload: {payload}")
        return False

def publish_command(client, command_payload):
    """Publishes a command to the command topic."""
    payload_str = json.dumps(command_payload)
    result = client.publish(CMD_TOPIC, payload_str, qos=1)
    result.wait_for_publish(timeout=5) # Wait for publish confirmation
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
         with print_lock:
            print(f"Tester Published Command: {payload_str} to {CMD_TOPIC}")
    else:
         with print_lock:
            print(f"Tester Failed to publish command: {payload_str}, RC: {result.rc}")

def prompt_action(message):
    """Prompts user for manual action."""
    with print_lock:
        input(f"\n>>> ACTION REQUIRED: {message}. Press Enter to continue...")

# --- Test Execution ---
if __name__ == "__main__":
    print("--- Starting SRM Integration Test Script ---")
    client = setup_mqtt_client()
    client.loop_start() # Start background thread for network traffic

    # Give time for connection and initial messages
    time.sleep(2)
    clear_message_queue() # Clear any initial retained messages

    # --- Scenario 1: Basic Presence Detection & Mode Change ---
    print("\n--- SCENARIO 1: Basic Presence & Mode Change ---")
    print("Verifying initial state...")
    if not check_status({"mode": "STANDBY", "presence_radar": False}):
        print("Initial state verification failed. Exiting.")
        sys.exit(1)

    prompt_action("Trigger the LD2410C radar sensor (wave hand etc.)")
    if not check_status({"mode": "PROACTIVE", "presence_radar": True}, timeout=10):
         print("Failed to verify PROACTIVE state after radar trigger.")
         # Continue testing other scenarios if desired
    else:
        print("PROACTIVE state verified.")


    prompt_action("STOP triggering the radar (ensure area is clear)")
    if not check_status({"mode": "STANDBY", "presence_radar": False}, timeout=15): # Allow more time to clear
        print("Failed to verify STANDBY state after radar clear.")
    else:
        print("STANDBY state verified.")

    # --- Scenario 2: Node-RED Command Handling ---
    print("\n--- SCENARIO 2: Command Handling ---")
    # Force PROACTIVE
    print("\nTesting FORCE PROACTIVE command...")
    publish_command(client, {"override_mode": "PROACTIVE"})
    if not check_status({"mode": "PROACTIVE", "override": "PROACTIVE"}):
        print("Failed to verify FORCE PROACTIVE.")
    else:
        print("FORCE PROACTIVE verified.")

    # Force STANDBY
    print("\nTesting FORCE STANDBY command...")
    publish_command(client, {"override_mode": "STANDBY"})
    if not check_status({"mode": "STANDBY", "override": "STANDBY"}):
        print("Failed to verify FORCE STANDBY.")
    else:
        print("FORCE STANDBY verified.")

    # Set AUTO
    print("\nTesting SET AUTO command...")
    publish_command(client, {"override_mode": "AUTO"})
    if not check_status({"mode": "STANDBY", "override": None}): # Should be standby if no presence
        print("Failed to verify SET AUTO (check override is None).")
    else:
        print("SET AUTO verified (override cleared).")
        # Test AUTO mode works
        prompt_action("Trigger the LD2410C radar sensor AGAIN (to test AUTO mode)")
        if not check_status({"mode": "PROACTIVE", "presence_radar": True, "override": None}, timeout=10):
             print("Failed to verify AUTO mode transition to PROACTIVE.")
        else:
            print("AUTO mode transition to PROACTIVE verified.")
            prompt_action("STOP triggering the radar AGAIN")
            if not check_status({"mode": "STANDBY", "presence_radar": False, "override": None}, timeout=15):
                print("Failed to verify AUTO mode transition to STANDBY.")
            else:
                print("AUTO mode transition to STANDBY verified.")

    # DISARM
    print("\nTesting DISARM command...")
    publish_command(client, {"mode": "DISARMED"})
    if not check_status({"armed": False}):
        print("Failed to verify DISARM.")
    else:
        print("DISARM verified.")

    # ARM
    print("\nTesting ARM command...")
    publish_command(client, {"mode": "ARMED"})
    if not check_status({"armed": True}):
        print("Failed to verify ARM.")
    else:
        print("ARM verified.")

    # --- Scenarios 3 & 4 require manual observation ---
    print("\n--- SCENARIOS 3 & 4: Alert Logic ---")
    print("These scenarios require manual observation of logs, MQTT alerts, and Node-RED.")
    print("Refer to the Integration Test Plan document for detailed steps.")
    print("Ensure system is ARMED and in AUTO mode before starting these.")
    prompt_action("Perform Scenario 3 (Hidden Intruder) steps manually")
    prompt_action("Perform Scenario 4 (Camera Tamper/Blind) steps manually (takes >5 mins)")

    # --- Scenarios 5 & 6 require manual actions ---
    print("\n--- SCENARIOS 5 & 6: Resilience ---")
    print("These scenarios require manual stopping/starting of services or the script.")
    print("Refer to the Integration Test Plan document for detailed steps.")
    prompt_action("Perform Scenario 5 (MQTT Broker Resilience) steps manually")
    prompt_action("Perform Scenario 6 (Script Restart Recovery) steps manually")


    # --- Cleanup ---
    print("\n--- Test Script Finished ---")
    client.loop_stop()
    client.disconnect()
    print("Tester Disconnected.")
