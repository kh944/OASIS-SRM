# -*- coding: utf-8 -*-
"""
OASIS Advanced Analytics Module v1.0
-------------------------------------
Runs alongside the OASIS Frigate Manager to provide:
1. Fall Detection using Pose Estimation on persons detected by Frigate.
2. Crowd Analytics & Occupancy Counting based on Frigate's person detections.

Assumptions:
- Frigate is running and publishing object detection events to MQTT.
- An RTSP stream of the camera feed is available (e.g., from go2rtc used by Frigate).
- The OASIS Frigate Manager is publishing system status (mode, armed) to MQTT.
- A Coral TPU is available for pose estimation.

Core Principles: Modular, MQTT-driven, respects Frigate Manager's mode.
"""

# --- Core Libraries ---
import time
import datetime
import os
import sys
import logging
import json
import threading
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
import numpy as np
import cv2 # OpenCV for RTSP stream and image manipulation

# --- AI / Edge TPU ---
try:
    from pycoral.adapters import common as pycoral_common
    from pycoral.utils.edgetpu import make_interpreter
    USE_PYCORAL = True
    logging.info("PyCoral library found. Will utilize Edge TPU for pose estimation.")
except ImportError:
    try:
        import tflite_runtime.interpreter as tflite
        def make_interpreter(model_path, delegate=None):
             # If not PyCoral, EdgeTPU delegate needs to be explicitly loaded for tflite_runtime
             if delegate and 'libedgetpu.so.1' in delegate:
                 return tflite.Interpreter(model_path=model_path,
                                           experimental_delegates=[tflite.load_delegate('libedgetpu.so.1')])
             return tflite.Interpreter(model_path=model_path)
        USE_PYCORAL = False
        logging.info("PyCoral not found. Using tflite_runtime. EdgeTPU delegate must be available for TPU use.")
    except ImportError:
        logging.critical("Neither PyCoral nor tflite_runtime found. AI Inference disabled. Install one.")
        make_interpreter = None; USE_PYCORAL = False; sys.exit(1) # AI is critical

# --- Configuration ---
# System Core
LOG_FILE = "/home/pi/Desktop/OASIS/oasis_advanced_analytics.log"
LOG_LEVEL = logging.INFO
MODULE_CLIENT_ID = "OASIS_Analytics_Module"

# MQTT Settings (Should match your Frigate Manager's broker)
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_USERNAME = None # Add if your broker uses authentication
MQTT_PASSWORD = None # Add if your broker uses authentication

# MQTT Topics for this module to SUBSCRIBE to
MQTT_TOPIC_FRIGATE_MANAGER_STATUS = "oasis/security/status" # From your Frigate Manager
MQTT_TOPIC_FRIGATE_EVENTS = "frigate/events"             # From Frigate NVR

# MQTT Topics for this module to PUBLISH to
MQTT_TOPIC_FALL_ALERTS = "oasis/analytics/fall_detected"
MQTT_TOPIC_OCCUPANCY_DATA = "oasis/analytics/occupancy"

# Camera/Stream Settings
RTSP_STREAM_URL = "rtsp://127.0.0.1:8554/pi_camera_h264" # Default from Frigate's go2rtc. CHECK YOUR FRIGATE/GO2RTC CONFIG
CAMERA_RESOLUTION_FOR_PROCESSING = (640, 480) # Resolution to process frames at (can be lower than stream)

# AI Settings for Pose Estimation
POSE_MODEL_PATH = "/home/pi/Desktop/OASIS/models/movenet_single_pose_lightning_ptq_edgetpu.tflite" # Ensure this path is correct
POSE_THRESHOLD = 0.3            # Minimum confidence score for detected keypoints
FALL_DETECTION_VERTICAL_THRESHOLD = 0.4 # Normalized Y coord (0=top, 1=bottom) threshold indicating potential fall
FALL_DETECTION_ASPECT_RATIO_THRESHOLD = 1.7 # BBox width/height ratio threshold for potential fall
FALL_COOLDOWN_SECONDS = 30      # Min time between fall alerts for the same tracked person proxy
PERSON_CLASS_NAME = "person"    # Label name for 'person' from Frigate events

# Crowd Analytics Settings
MAX_OCCUPANCY_FOR_ALERT = 15      # Example: Alert if occupancy exceeds this
OCCUPANCY_PUBLISH_INTERVAL = 60 # Seconds

# --- Global State Variables ---
is_proactive_mode = False         # Is the system in PROACTIVE mode (from Frigate Manager)
system_armed = False              # Is the system ARMED (from Frigate Manager)
current_occupancy = 0             # Current estimated number of people
last_occupancy_publish_time = 0
# For fall detection cooldown and simple tracking: {track_id: {'last_alert_time': timestamp, 'bbox_center': (x,y), 'last_seen': timestamp}}
fall_track_proxies = {}
FALL_TRACKING_MAX_DIST_PX = 75 # Max pixel distance to associate a new detection with an existing fall proxy
FALL_TRACKING_PROXY_TIMEOUT_SEC = FALL_COOLDOWN_SECONDS * 2 # How long to keep a proxy without seeing it

# AI Engine Instance
ai_engine_instance = None
rtsp_capture = None
rtsp_thread = None
rtsp_frame_lock = threading.Lock()
latest_rtsp_frame = None
rtsp_thread_running = False

# Logging Setup
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    try: os.makedirs(log_dir)
    except OSError as e: logging.error(f"Failed to create log directory {log_dir}: {e}")

logging.basicConfig(level=LOG_LEVEL,
                    format='%(asctime)s %(levelname)-8s [%(threadName)s:%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[logging.FileHandler(LOG_FILE, mode='a'),
                              logging.StreamHandler(sys.stdout)])

# --- Helper Functions ---
def scale_bbox_from_frigate(bbox_frigate, original_frame_width, original_frame_height):
    """
    Frigate's bounding box is [x, y, w, h] where x,y is top-left.
    Converts it to [xmin, ymin, xmax, ymax] in pixel coordinates.
    """
    x, y, w, h = bbox_frigate
    xmin = int(x)
    ymin = int(y)
    xmax = int(x + w)
    ymax = int(y + h)
    # Ensure coordinates are within frame boundaries
    xmin = max(0, xmin); ymin = max(0, ymin)
    xmax = min(original_frame_width -1, xmax); ymax = min(original_frame_height -1, ymax)
    return [xmin, ymin, xmax, ymax]

def get_bbox_center(bbox_pixels):
    xmin, ymin, xmax, ymax = bbox_pixels
    return int((xmin + xmax) / 2), int((ymin + ymax) / 2)

# --- RTSP Stream Reader Thread ---
def rtsp_reader_loop():
    """Continuously reads frames from the RTSP stream and updates the latest_rtsp_frame."""
    global latest_rtsp_frame, rtsp_capture, rtsp_thread_running
    logging.info(f"RTSP reader thread started for stream: {RTSP_STREAM_URL}")
    
    retry_delay = 5 # seconds
    max_retries = 5
    retries = 0

    while rtsp_thread_running:
        if rtsp_capture is None or not rtsp_capture.isOpened():
            if retries < max_retries:
                logging.warning(f"RTSP stream not open. Attempting to reconnect in {retry_delay}s (Attempt {retries+1}/{max_retries})...")
                time.sleep(retry_delay)
                try:
                    rtsp_capture = cv2.VideoCapture(RTSP_STREAM_URL, cv2.CAP_FFMPEG)
                    if rtsp_capture.isOpened():
                        logging.info("RTSP stream reconnected successfully.")
                        retries = 0 # Reset retries on successful connection
                    else:
                        logging.error("Failed to reopen RTSP stream.")
                        rtsp_capture = None # Ensure it's None if open failed
                        retries +=1
                except Exception as e:
                    logging.error(f"Exception while trying to open RTSP stream: {e}")
                    rtsp_capture = None
                    retries += 1
                continue
            else:
                logging.error(f"Max retries ({max_retries}) reached for RTSP stream. Thread stopping.")
                rtsp_thread_running = False # Stop the thread
                break

        ret, frame = rtsp_capture.read()
        if ret:
            with rtsp_frame_lock:
                latest_rtsp_frame = frame.copy()
            retries = 0 # Reset retries on successful frame read
        else:
            logging.warning("Failed to grab frame from RTSP stream. Will attempt to reopen.")
            if rtsp_capture:
                rtsp_capture.release()
            rtsp_capture = None # Force re-open
            retries +=1 # Count this as a retry attempt for the stream
            time.sleep(1) # Brief pause before trying to reopen in the loop

        # Small delay to prevent busy-looping if read is too fast or stream is problematic
        time.sleep(0.01) 

    if rtsp_capture:
        rtsp_capture.release()
    logging.info("RTSP reader thread finished.")

# --- AI Inference Engine (Pose Estimation Only) ---
class PoseAIInferenceEngine:
    def __init__(self):
        self.pose_interpreter = None
        self.pose_input_details = None
        self.pose_output_details = None
        self.pose_height = 0
        self.pose_width = 0
        self.coral_available = USE_PYCORAL

    def load_pose_estimator(self, model_path):
        if not make_interpreter: return False
        try:
            logging.info(f"Loading Pose Estimation model: {model_path}")
            # For tflite_runtime, specify EdgeTPU delegate if model is compiled for it
            delegate_path = 'libedgetpu.so.1' if not USE_PYCORAL and "_edgetpu" in model_path else None
            self.pose_interpreter = make_interpreter(model_path, delegate=delegate_path)
            
            self.pose_interpreter.allocate_tensors()
            self.pose_input_details = self.pose_interpreter.get_input_details()
            self.pose_output_details = self.pose_interpreter.get_output_details()
            self.pose_height = self.pose_input_details[0]['shape'][1]
            self.pose_width = self.pose_input_details[0]['shape'][2]
            logging.info(f"Pose Estimation Model loaded. Input shape: ({self.pose_input_details[0]['shape']}), Expected: H={self.pose_height}, W={self.pose_width}")
            return True
        except Exception as e:
            logging.error(f"Failed to load Pose Estimation model: {e}", exc_info=True)
            if "Could not open Edge TPU device" in str(e) or "Failed to load delegate" in str(e): 
                self.coral_available = False
                logging.warning("EdgeTPU delegate failed to load. Pose estimation might run on CPU if model supports it, or fail.")
            self.pose_interpreter = None
            return False

    def estimate_pose(self, frame_np, person_bbox_pixels_original_frame):
        if not self.pose_interpreter or frame_np is None: return None, 0.0
        
        xmin, ymin, xmax, ymax = person_bbox_pixels_original_frame
        
        # Ensure ROI coordinates are valid
        if xmin >= xmax or ymin >= ymax:
            logging.debug(f"Invalid ROI dimensions: {person_bbox_pixels_original_frame}, skipping pose estimation.")
            return None, 0.0

        # Crop the person ROI from the original frame with some padding
        pad_w = int((xmax - xmin) * 0.1); pad_h = int((ymax - ymin) * 0.1)
        h_orig, w_orig, _ = frame_np.shape
        
        crop_xmin = max(0, xmin - pad_w); crop_ymin = max(0, ymin - pad_h)
        crop_xmax = min(w_orig, xmax + pad_w); crop_ymax = min(h_orig, ymax + pad_h)

        person_roi = frame_np[crop_ymin:crop_ymax, crop_xmin:crop_xmax]
        
        if person_roi.size == 0:
            logging.debug(f"Empty ROI after cropping for bbox {person_bbox_pixels_original_frame}, skipping pose.")
            return None, 0.0

        try:
            img_resized_roi = cv2.resize(person_roi, (self.pose_width, self.pose_height))
            
            input_tensor_dtype = self.pose_input_details[0]['dtype']
            if input_tensor_dtype == np.uint8:
                input_data = np.expand_dims(img_resized_roi.astype(np.uint8), axis=0)
            elif input_tensor_dtype == np.float32:
                input_data = np.expand_dims(img_resized_roi.astype(np.float32) / 255.0, axis=0)
            else:
                logging.error(f"Unsupported pose model input dtype: {input_tensor_dtype}")
                return None, 0.0

            if USE_PYCORAL and self.coral_available:
                pycoral_common.set_input(self.pose_interpreter, input_data)
            else:
                self.pose_interpreter.set_tensor(self.pose_input_details[0]['index'], input_data)

            self.pose_interpreter.invoke()
            pose_output = self.pose_interpreter.get_tensor(self.pose_output_details[0]['index'])[0][0] # Shape (17, 3) for MoveNet

            valid_scores = [kp[2] for kp in pose_output if kp[2] >= POSE_THRESHOLD]
            pose_confidence = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0

            keypoints_frame_coords = []
            roi_h, roi_w, _ = person_roi.shape # Dimensions of the actually cropped ROI
            for y_norm_model, x_norm_model, score in pose_output: # These are normalized to model input size
                if score >= POSE_THRESHOLD:
                    # Convert model-normalized (0-1) to pixel coords within the *resized ROI*
                    kp_x_resized_roi = x_norm_model * self.pose_width 
                    kp_y_resized_roi = y_norm_model * self.pose_height
                    
                    # Scale these coordinates back to the *original ROI* size before padding
                    kp_x_orig_roi = (kp_x_resized_roi / self.pose_width) * roi_w
                    kp_y_orig_roi = (kp_y_resized_roi / self.pose_height) * roi_h
                    
                    # Add ROI offset (crop_xmin, crop_ymin) to get coords relative to the full original frame
                    kp_x_frame = int(kp_x_orig_roi + crop_xmin)
                    kp_y_frame = int(kp_y_orig_roi + crop_ymin)
                    keypoints_frame_coords.append({'x': kp_x_frame, 'y': kp_y_frame, 'score': float(score)})
                else:
                    keypoints_frame_coords.append(None)
            
            return keypoints_frame_coords, pose_confidence
        except Exception as e:
            logging.error(f"Error during pose estimation for bbox {person_bbox_pixels_original_frame}: {e}", exc_info=True)
            return None, 0.0

# --- Crowd Analytics ---
class CrowdAnalytics:
    def __init__(self):
        self.current_person_count = 0
        self.tracked_person_ids_this_interval = set() # To count unique persons from Frigate events

    def update_occupancy(self, frigate_event_data):
        """Updates occupancy based on a Frigate event.
           Frigate events can be 'new', 'update', or 'end'.
           We count unique person IDs seen in 'new' or 'update' events.
        """
        event_type = frigate_event_data.get('type')
        
        if event_type == 'new' or event_type == 'update':
            after_data = frigate_event_data.get('after', {})
            if after_data.get('label') == PERSON_CLASS_NAME:
                person_id = after_data.get('id')
                if person_id:
                    self.tracked_person_ids_this_interval.add(person_id)
        
        # The actual count is the size of the set
        self.current_person_count = len(self.tracked_person_ids_this_interval)
        return self.current_person_count

    def reset_interval_tracking(self):
        """Resets the set of tracked person IDs for the new interval."""
        self.tracked_person_ids_this_interval.clear()
        self.current_person_count = 0 # Also reset count

    def get_current_count(self):
        return self.current_person_count

# --- MQTT Client ---
class MQTTClientWrapper:
    def __init__(self, broker, port, client_id, username, password, on_message_callback):
        self.broker = broker
        self.port = port
        self.client_id = client_id
        self.username = username
        self.password = password
        self.on_message_callback = on_message_callback
        self.client = mqtt.Client(client_id=self.client_id, callback_api_version=CallbackAPIVersion.VERSION1)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message_internal # Use internal handler
        self.client.on_disconnect = self._on_disconnect
        self.connected = False
        self._connect_thread = None

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"MQTT connected to {self.broker}:{self.port}")
            self.connected = True
            client.subscribe(MQTT_TOPIC_FRIGATE_MANAGER_STATUS)
            logging.info(f"MQTT Subscribed to: {MQTT_TOPIC_FRIGATE_MANAGER_STATUS}")
            client.subscribe(MQTT_TOPIC_FRIGATE_EVENTS + "/#") # Subscribe to all sub-topics of frigate events
            logging.info(f"MQTT Subscribed to: {MQTT_TOPIC_FRIGATE_EVENTS}/#")
        else:
            logging.error(f"MQTT connection failed, code {rc}: {mqtt.connack_string(rc)}")
            self.connected = False

    def _on_disconnect(self, client, userdata, rc):
        logging.warning(f"MQTT disconnected, code {rc}. Will attempt to reconnect.")
        self.connected = False

    def _on_message_internal(self, client, userdata, msg):
        # This internal handler calls the user-provided callback in a new thread
        # to avoid blocking the MQTT client's network loop, especially if processing is long.
        threading.Thread(target=self.on_message_callback, args=(msg.topic, msg.payload), daemon=True).start()

    def connect_async(self):
        if self._connect_thread and self._connect_thread.is_alive():
            logging.warning("MQTT connection attempt already in progress.")
            return
        self._connect_thread = threading.Thread(target=self._connect_blocking, daemon=True)
        self._connect_thread.start()

    def _connect_blocking(self):
        while True:
            try:
                if self.username and self.password:
                    self.client.username_pw_set(self.username, self.password)
                
                lwt_payload = json.dumps({"status": "offline", "module": MODULE_CLIENT_ID})
                # Publish LWT to a general analytics status topic or a specific one for this module
                self.client.will_set(f"oasis/analytics/{MODULE_CLIENT_ID}/status", payload=lwt_payload, qos=1, retain=True)

                logging.info(f"Attempting MQTT connection to {self.broker}:{self.port}...")
                self.client.connect(self.broker, self.port, keepalive=60)
                self.client.loop_start() # Handles PINGs and reconnections

                connect_timeout = time.time() + 15
                while not self.connected and time.time() < connect_timeout:
                    time.sleep(0.1)
                
                if self.connected:
                    logging.info("MQTT connection loop started.")
                    # Publish online status
                    online_payload = json.dumps({"status": "online", "module": MODULE_CLIENT_ID, "timestamp": time.time()})
                    self.publish(f"oasis/analytics/{MODULE_CLIENT_ID}/status", online_payload, retain=True)
                    break 
                else:
                    self.client.loop_stop()
                    logging.warning("MQTT connection timed out before on_connect.")

            except Exception as e:
                logging.error(f"MQTT connection error: {e}")
            logging.info("Retrying MQTT connection in 15 seconds...")
            time.sleep(15)
            
    def publish(self, topic, payload_dict_or_str, retain=False, qos=1):
        if not self.connected:
            logging.warning(f"MQTT publish failed (Not connected): Topic={topic}")
            return False
        try:
            payload_str = json.dumps(payload_dict_or_str) if isinstance(payload_dict_or_str, dict) else payload_dict_or_str
            result, mid = self.client.publish(topic, payload_str, qos=qos, retain=retain)
            if result == mqtt.MQTT_ERR_SUCCESS:
                logging.debug(f"MQTT Published: Topic='{topic}', QoS={qos}, Retain={retain}, Payload='{payload_str[:100]}...'")
                return True
            else:
                logging.warning(f"MQTT publish failed, code {result}: {mqtt.error_string(result)}")
                return False
        except Exception as e:
            logging.error(f"Error publishing MQTT message to {topic}: {e}")
            return False

    def disconnect(self):
        logging.info("Disconnecting MQTT client.")
        offline_payload = json.dumps({"status": "offline", "module": MODULE_CLIENT_ID, "timestamp": time.time()})
        self.publish(f"oasis/analytics/{MODULE_CLIENT_ID}/status", offline_payload, retain=True) # Best effort
        time.sleep(0.2)
        self.client.loop_stop()
        self.client.disconnect()
        self.connected = False

# --- Main Logic ---
def process_mqtt_message(topic, payload):
    """Handles incoming MQTT messages."""
    global is_proactive_mode, system_armed, ai_engine_instance, crowd_analyzer, latest_rtsp_frame, fall_track_proxies

    try:
        payload_str = payload.decode('utf-8')
        data = json.loads(payload_str)

        if topic == MQTT_TOPIC_FRIGATE_MANAGER_STATUS:
            new_mode = data.get('mode', DEFAULT_MODE).upper() # Use your Frigate Manager's default if not present
            new_armed_status = data.get('armed', True) # Use your Frigate Manager's default

            if new_mode != ("PROACTIVE" if is_proactive_mode else "STANDBY"): # Check for actual change
                 logging.info(f"Frigate Manager Mode changed to: {new_mode}")
            is_proactive_mode = (new_mode == "PROACTIVE")
            
            if new_armed_status != system_armed: # Check for actual change
                logging.info(f"Frigate Manager Armed status changed to: {new_armed_status}")
            system_armed = new_armed_status
            
            # If switching out of proactive, clear fall tracking proxies
            if not is_proactive_mode:
                fall_track_proxies.clear()


        elif topic.startswith(MQTT_TOPIC_FRIGATE_EVENTS.split('/')[0]): # e.g. "frigate/events"
            if not is_proactive_mode: # Only process Frigate events if analytics module should be active
                return

            event_type = data.get('type')
            
            # Update occupancy based on any relevant Frigate event for persons
            if data.get('after', {}).get('label') == PERSON_CLASS_NAME or \
               data.get('before', {}).get('label') == PERSON_CLASS_NAME:
                crowd_analyzer.update_occupancy(data)

            # For fall detection, we act on 'new' or 'update' events for persons
            if event_type == 'new' or event_type == 'update':
                after_data = data.get('after', {})
                if after_data.get('label') == PERSON_CLASS_NAME:
                    person_id = after_data.get('id') # Frigate's event ID for the person
                    bbox_frigate = after_data.get('box') # Frigate's box: [x, y, w, h]
                    
                    if not bbox_frigate or len(bbox_frigate) != 4:
                        logging.warning(f"Missing or invalid bounding box in Frigate event for person {person_id}")
                        return

                    current_frame_for_pose = None
                    with rtsp_frame_lock:
                        if latest_rtsp_frame is not None:
                            current_frame_for_pose = latest_rtsp_frame.copy()
                    
                    if current_frame_for_pose is None:
                        logging.warning(f"No RTSP frame available for pose estimation on person {person_id}")
                        return

                    # Frigate's bounding box is relative to its detection resolution.
                    # For simplicity, we assume the RTSP stream is at a known resolution
                    # (e.g. CAMERA_RESOLUTION_FOR_PROCESSING) or we use Frigate's camera resolution if available in event.
                    # Here, we'll assume RTSP stream is what we process directly.
                    # The bbox from Frigate might need scaling if Frigate's detect resolution differs from RTSP stream resolution.
                    # For this example, let's assume Frigate's 'region' or 'camera' dimensions are what bbox is relative to.
                    # This part might need refinement based on your exact Frigate event structure and resolutions.
                    # Let's assume the RTSP frame (current_frame_for_pose) is the reference.
                    frame_h, frame_w, _ = current_frame_for_pose.shape
                    
                    # Convert Frigate's [x,y,w,h] to [xmin,ymin,xmax,ymax] for our AI engine
                    # This assumes Frigate's box coordinates are already scaled to the full original frame.
                    # If Frigate's box is normalized, you'd multiply by frame_w, frame_h.
                    # Frigate's `box` is [x, y, width, height] in pixels of the *detection resolution*.
                    # We need to ensure our `current_frame_for_pose` matches this or scale appropriately.
                    # For simplicity, if your RTSP_STREAM_URL is the same as Frigate's input, and detection res is same,
                    # then bbox_frigate can be used directly after conversion.
                    
                    # Let's assume bbox_frigate is [x_min, y_min, width, height] in pixels of the frame Frigate processed.
                    # We need to ensure our current_frame_for_pose is consistent.
                    # The `box` field in Frigate events is usually [x, y, w, h] in pixels.
                    person_bbox_pixels = scale_bbox_from_frigate(bbox_frigate, frame_w, frame_h)

                    keypoints, pose_score = ai_engine_instance.estimate_pose(current_frame_for_pose, person_bbox_pixels)

                    if keypoints:
                        if analyze_pose_for_fall(person_bbox_pixels, keypoints):
                            center_px = get_bbox_center(person_bbox_pixels)
                            now_time = time.monotonic()
                            
                            # Simple proxy tracking for cooldown
                            matched_proxy_id = None
                            min_dist = FALL_TRACKING_MAX_DIST_PX
                            for proxy_id, proxy_data in list(fall_track_proxies.items()): # Iterate on copy for safe deletion
                                if (now_time - proxy_data['last_seen']) > FALL_TRACKING_PROXY_TIMEOUT_SEC:
                                    del fall_track_proxies[proxy_id] # Remove stale proxy
                                    continue
                                dist = np.sqrt((center_px[0] - proxy_data['bbox_center'][0])**2 + \
                                               (center_px[1] - proxy_data['bbox_center'][1])**2)
                                if dist < min_dist:
                                    min_dist = dist
                                    matched_proxy_id = proxy_id
                            
                            can_alert = True
                            if matched_proxy_id:
                                fall_track_proxies[matched_proxy_id]['last_seen'] = now_time
                                fall_track_proxies[matched_proxy_id]['bbox_center'] = center_px # Update center
                                if (now_time - fall_track_proxies[matched_proxy_id]['last_alert_time']) < FALL_COOLDOWN_SECONDS:
                                    can_alert = False
                                else: # Cooldown passed for this proxy
                                     fall_track_proxies[matched_proxy_id]['last_alert_time'] = now_time
                            else: # New fall proxy
                                matched_proxy_id = person_id # Use Frigate's person ID as proxy ID
                                fall_track_proxies[matched_proxy_id] = {
                                    'last_alert_time': now_time,
                                    'bbox_center': center_px,
                                    'last_seen': now_time
                                }

                            if can_alert and system_armed: # Only alert if system is armed
                                logging.warning(f"Fall Detected for person ID {person_id} at {center_px}!")
                                alert_payload = {
                                    "timestamp": datetime.datetime.now().isoformat(),
                                    "person_id": person_id,
                                    "bounding_box_pixels": person_bbox_pixels,
                                    "estimated_pose_score": pose_score,
                                    "camera_node_id": MODULE_CLIENT_ID # Or a more specific camera ID
                                }
                                mqtt_client.publish(MQTT_TOPIC_FALL_ALERTS, alert_payload)
                                # Optionally, could trigger a snapshot via an MQTT command to Frigate Manager or another service
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON payload on topic {topic}: {payload_str}")
    except UnicodeDecodeError:
        logging.error(f"Failed to decode payload as UTF-8 on topic {topic}")
    except Exception as e:
        logging.error(f"Error processing MQTT message on topic {topic}: {e}", exc_info=True)

def analyze_pose_for_fall(person_bbox_pixels, pose_keypoints):
    if pose_keypoints is None: return False
    
    # Example: Use MoveNet keypoint indices (0:Nose, 5:L Shldr, 6:R Shldr, 11:L Hip, 12:R Hip)
    # This is a simplified heuristic. More robust fall detection would involve analyzing
    # keypoint velocities, orientation changes, and temporal consistency.
    key_body_indices = [0, 5, 6, 11, 12] 
    valid_y_coords = []
    for i, kp in enumerate(pose_keypoints):
        if kp and i in key_body_indices:
            valid_y_coords.append(kp['y'])
    
    if not valid_y_coords: return False

    # This is a very basic heuristic: if average Y of key body points is low in the frame
    # AND the bounding box is wide (aspect ratio).
    # Assumes frame height is known or can be inferred (e.g. from RTSP stream).
    # For this example, we don't have direct frame height here, so this logic needs refinement
    # if you use normalized keypoints. If keypoints are in pixels, you need frame_height.
    # The `estimate_pose` returns keypoints in original frame coordinates.
    
    avg_y_coord = np.mean(valid_y_coords)
    
    # Assuming CAMERA_RESOLUTION_FOR_PROCESSING gives the height of the frame used for pose.
    # This might not be true if RTSP stream has different resolution.
    # For robustness, pass frame_height to this function or get it from current_frame_for_pose.
    # Let's assume the keypoints are already in pixel coordinates of the processed frame.
    # We need a reference for "low". If using CAMERA_RESOLUTION_FOR_PROCESSING:
    frame_h_ref = CAMERA_RESOLUTION_FOR_PROCESSING[1] 
    avg_y_norm = avg_y_coord / frame_h_ref # Normalize based on assumed processing height

    is_low = avg_y_norm > (1.0 - FALL_DETECTION_VERTICAL_THRESHOLD)

    xmin, ymin, xmax, ymax = person_bbox_pixels
    bbox_w = xmax - xmin
    bbox_h = ymax - ymin
    aspect_ratio = bbox_w / bbox_h if bbox_h > 5 else 1.0
    is_wide = aspect_ratio > FALL_DETECTION_ASPECT_RATIO_THRESHOLD
    
    potential_fall = is_low and is_wide
    if potential_fall:
        logging.debug(f"Fall heuristics met: low={is_low} (avg_y_norm={avg_y_norm:.2f}), wide={is_wide} (aspect={aspect_ratio:.2f})")
    return potential_fall

# --- Main Execution ---
if __name__ == "__main__":
    logging.info(f"====== {MODULE_CLIENT_ID} Starting Up ======")

    ai_engine_instance = PoseAIInferenceEngine()
    if not ai_engine_instance.load_pose_estimator(POSE_MODEL_PATH):
        logging.critical("Failed to load pose estimation model. Fall detection will not work. Exiting.")
        sys.exit(1)

    crowd_analyzer = CrowdAnalytics()

    mqtt_client = MQTTClientWrapper(MQTT_BROKER, MQTT_PORT, MODULE_CLIENT_ID, MQTT_USERNAME, MQTT_PASSWORD, process_mqtt_message)
    mqtt_client.connect_async()

    # Start RTSP reader thread
    rtsp_thread_running = True
    rtsp_thread = threading.Thread(target=rtsp_reader_loop, daemon=True)
    rtsp_thread.start()
    
    logging.info("Waiting for MQTT connection and RTSP stream to stabilize...")
    time.sleep(5) # Give some time for connections

    try:
        while True:
            if is_proactive_mode: # Only publish occupancy if proactive
                now = time.monotonic()
                if (now - last_occupancy_publish_time) >= OCCUPANCY_PUBLISH_INTERVAL:
                    current_count = crowd_analyzer.get_current_count()
                    occupancy_payload = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "occupancy_count": current_count,
                        "camera_node_id": MODULE_CLIENT_ID
                    }
                    mqtt_client.publish(MQTT_TOPIC_OCCUPANCY_DATA, occupancy_payload)
                    last_occupancy_publish_time = now
                    # Reset tracked IDs for the next interval after publishing
                    crowd_analyzer.reset_interval_tracking() 
                    
                    if current_count > MAX_OCCUPANCY_FOR_ALERT and system_armed:
                         logging.warning(f"Overcrowding detected! Count: {current_count}")
                         mqtt_client.publish(MQTT_TOPIC_FALL_ALERTS, { # Re-using fall alert topic for general critical alerts
                             "timestamp": datetime.datetime.now().isoformat(),
                             "type": "overcrowding",
                             "count": current_count,
                             "limit": MAX_OCCUPANCY_FOR_ALERT,
                             "camera_node_id": MODULE_CLIENT_ID
                         })


            # Clean up stale fall track proxies periodically even if not proactive
            # to prevent memory buildup if system stays non-proactive for long.
            now_time_main = time.monotonic()
            for proxy_id, proxy_data in list(fall_track_proxies.items()):
                if (now_time_main - proxy_data['last_seen']) > FALL_TRACKING_PROXY_TIMEOUT_SEC:
                    logging.debug(f"Removing stale fall track proxy ID: {proxy_id}")
                    del fall_track_proxies[proxy_id]
            
            time.sleep(1) # Main loop check interval

    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Shutting down...")
    finally:
        rtsp_thread_running = False
        if rtsp_thread:
            rtsp_thread.join(timeout=5)
        if mqtt_client:
            mqtt_client.disconnect()
        if rtsp_capture:
            rtsp_capture.release()
        cv2.destroyAllWindows() # Just in case any debug windows were opened
        logging.info(f"====== {MODULE_CLIENT_ID} Shutdown Complete ======")
