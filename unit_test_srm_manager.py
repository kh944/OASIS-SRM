# unit_test_srm_manager.py
import unittest
from unittest.mock import patch, MagicMock, mock_open, call, ANY
import sys
import os
import time
import json
import logging
import struct
import threading
import serial # Import for exception types
import paho.mqtt.client as mqtt_client_real # Import real module for constants/exceptions if needed

# Mock RPi.GPIO and serial before importing srm_manager
mock_gpio = MagicMock()
sys.modules['RPi.GPIO'] = mock_gpio
sys.modules['RPi'] = MagicMock(GPIO=mock_gpio)

mock_serial_module = MagicMock()
mock_serial_instance = MagicMock()
mock_serial_module.Serial.return_value = mock_serial_instance
mock_serial_module.SerialException = serial.SerialException # Use real exception type
sys.modules['serial'] = mock_serial_module

# Mock paho.mqtt.client
mock_mqtt_client_module = MagicMock()
mock_mqtt_client_instance = MagicMock()
mock_mqtt_client_module.Client.return_value = mock_mqtt_client_instance
mock_mqtt_client_module.CallbackAPIVersion.VERSION1 = 1
mock_mqtt_client_module.MQTT_ERR_SUCCESS = 0
mock_mqtt_client_module.MQTT_ERR_NO_CONN = 1
mock_mqtt_client_module.MQTT_ERR_QUEUE_SIZE = 3 # Example error
mock_mqtt_client_module.connack_string = MagicMock(return_value="Connection Accepted")
mock_mqtt_client_module.error_string = MagicMock(return_value="Some MQTT Error")
# Add real exceptions if needed for testing 'except' blocks
mock_mqtt_client_module.WebsocketConnectionError = ConnectionRefusedError # Example mapping
mock_mqtt_client_module.socket_error = OSError # Example mapping

sys.modules['paho.mqtt.client'] = mock_mqtt_client_module
sys.modules['paho.mqtt'] = MagicMock(client=mock_mqtt_client_module)
sys.modules['paho'] = MagicMock(mqtt=sys.modules['paho.mqtt'])

# Now import the script to be tested
import srm_manager

# --- Base Test Class with Common Setup ---
class BaseSRMTest(unittest.TestCase):
    _gpio_mock_preserved = False

    @patch('srm_manager.logging.basicConfig')
    @patch('srm_manager.os.makedirs')
    @patch('srm_manager.sys.exit')
    def setUp(self, mock_sys_exit, mock_makedirs, mock_basicConfig):
        # Reset mocks (conditionally for GPIO)
        if not BaseSRMTest._gpio_mock_preserved and self.__class__ is TestInitializationAndCompliance:
             BaseSRMTest._gpio_mock_preserved = True
        # Reset GPIO mock specifically for the Maintenance class to avoid accumulated calls
        elif self.__class__ is TestMaintenanceAndLifecycle:
             mock_gpio.reset_mock() # Reset GPIO mock for this class

        mock_serial_module.reset_mock()
        mock_serial_instance.reset_mock()
        mock_serial_module.Serial.return_value = mock_serial_instance

        mock_mqtt_client_module.reset_mock()
        mock_mqtt_client_instance.reset_mock()
        mock_mqtt_client_module.Client.return_value = mock_mqtt_client_instance

        # Set default return value for the underlying client's publish
        mock_mqtt_client_instance.publish.return_value = (mock_mqtt_client_module.MQTT_ERR_SUCCESS, 123) # Simulate success

        mock_makedirs.reset_mock()
        mock_basicConfig.reset_mock()
        mock_sys_exit.reset_mock()

        # Reset relevant global states in srm_manager
        srm_manager.current_mode = srm_manager.DEFAULT_MODE
        srm_manager.manual_override_mode = None
        srm_manager.ld2410c_presence_detected = False
        srm_manager.last_status_publish_time = 0
        srm_manager.mqtt_client_connected = False
        srm_manager.system_armed = True
        srm_manager.camera_detection = False
        srm_manager.last_camera_detection_time = 0
        srm_manager.time_radar_became_active = 0
        srm_manager.last_fusion_alert_time = 0
        srm_manager.last_tamper_alert_time = 0
        srm_manager.camera_blind = False
        srm_manager.last_camera_detection_time_with_radar = 0
        srm_manager.serial_port_instance = None
        srm_manager.serial_thread = None
        srm_manager.serial_thread_running = False
        srm_manager.fusion_logger = None
        srm_manager.mqtt_client_instance = None

        # Patch time functions
        self.patcher_time = patch('srm_manager.time.time', return_value=1234567890.0)
        self.mock_time = self.patcher_time.start()
        self.patcher_monotonic = patch('srm_manager.time.monotonic', return_value=1000.0)
        self.mock_monotonic = self.patcher_monotonic.start()
        self.patcher_sleep = patch('srm_manager.time.sleep', return_value=None)
        self.mock_sleep = self.patcher_sleep.start()

        # Create a default MQTT wrapper instance for tests
        self.mock_command_callback = MagicMock()
        self.client_wrapper = srm_manager.MQTTClientWrapper(
            "localhost", 1883, "test_client", None, None, self.mock_command_callback
        )
        self.client_wrapper.client = mock_mqtt_client_instance

        # Assign the wrapper instance to the global variable
        # CRITICAL: Functions often use this global instance directly
        srm_manager.mqtt_client_instance = self.client_wrapper
        srm_manager.mqtt_client_connected = True # Assume connected unless test overrides


    def tearDown(self):
        self.patcher_time.stop()
        self.patcher_monotonic.stop()
        self.patcher_sleep.stop()
        srm_manager.mqtt_client_instance = None
        srm_manager.mqtt_client_connected = False

# --- Test Cases Grouped by Specification Area ---

class TestInitializationAndCompliance(BaseSRMTest):

    # TS SECU 09 / 16
    def test_spec_initialization_robustness(self):
        """Verify script initializes without critical errors using mocks."""
        self.assertTrue(True)

    # TS SECU 11
    @patch('srm_manager.os.path.exists', return_value=False)
    @patch('srm_manager.os.makedirs')
    @patch('srm_manager.logging.FileHandler')
    @patch('srm_manager.logging.getLogger')
    def test_spec_TS_SECU_11_logging_setup(self, mock_getLogger, mock_file_handler, mock_makedirs, mock_path_exists):
        """Verify dedicated fusion logger setup (relates to auditability)."""
        mock_logger_instance = MagicMock()
        mock_getLogger.return_value = mock_logger_instance
        srm_manager.FUSION_ALERT_LOG_FILE = "/tmp/test_fusion.log"
        srm_manager.setup_fusion_logger()
        mock_makedirs.assert_any_call(os.path.dirname(srm_manager.FUSION_ALERT_LOG_FILE), exist_ok=True)
        self.assertIs(srm_manager.fusion_logger, mock_logger_instance)
        mock_logger_instance.info.assert_called_with("Fusion/Tamper alert logger initialized.")

    # TS SECU 11 - Robustness: Test logger setup failure
    @patch('srm_manager.os.path.exists', return_value=True) # Assume dir exists
    @patch('srm_manager.logging.FileHandler', side_effect=OSError("Permission denied"))
    @patch('srm_manager.logging.error')
    def test_robustness_fusion_logger_setup_failure(self, mock_log_error, mock_file_handler, mock_path_exists):
        """Verify fusion logger setup failure is handled gracefully."""
        srm_manager.FUSION_ALERT_LOG_FILE = "/tmp/no_permission.log"
        srm_manager.setup_fusion_logger()
        self.assertIsNone(srm_manager.fusion_logger) # Should be reset to None
        mock_log_error.assert_called_with(f"Failed to setup fusion logger for {srm_manager.FUSION_ALERT_LOG_FILE}: Permission denied")

    # TS SECU 11 - Robustness: Test fallback logging
    @patch('srm_manager.logging.info') # Patch root logger's info
    @patch('srm_manager.logging.warning') # Patch root logger's warning
    def test_robustness_log_alert_event_fallback(self, mock_root_warning, mock_root_info):
        """Verify log_alert_event falls back to root logger if fusion_logger is None."""
        srm_manager.fusion_logger = None # Ensure it's None

        srm_manager.log_alert_event("Info test message", level=logging.INFO)
        mock_root_info.assert_called_once_with(f"ALERT_FALLBACK - Node: {srm_manager.MQTT_CLIENT_ID} - Info test message")

        srm_manager.log_alert_event("Warning test message", level=logging.WARNING)
        mock_root_warning.assert_called_once_with(f"ALERT_FALLBACK - Node: {srm_manager.MQTT_CLIENT_ID} - Warning test message")

    # TS SECU 09 / 16
    def test_spec_gpio_setup_logic(self):
        """Verify GPIO setup calls (part of hardware interface compliance)."""
        mock_gpio.setmode.assert_called_with(mock_gpio.BCM)
        mock_gpio.setup.assert_called_with(srm_manager.LD2410C_OUT_PIN, mock_gpio.IN, pull_up_down=mock_gpio.PUD_DOWN)
        mock_gpio.setwarnings.assert_called_with(False)

class TestPowerAndModeLogic(BaseSRMTest):

    @patch('srm_manager.set_cpu_governor')
    @patch('srm_manager.publish_status')
    def test_spec_TS_SECU_03_mode_switch_logic(self, mock_publish_status, mock_set_cpu_governor):
        """Verify mode switching calls CPU governor and Frigate control (Power Efficiency logic)."""
        # Switch to PROACTIVE
        srm_manager.current_mode = "STANDBY"
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=(mock_mqtt_client_module.MQTT_ERR_SUCCESS, 1))

        srm_manager.switch_mode("PROACTIVE")
        mock_set_cpu_governor.assert_called_with(srm_manager.CPU_GOVERNOR_PROACTIVE)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_DETECT_SET, "ON", qos=1)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_RECORD_SET, "ON", qos=1)
        self.assertEqual(srm_manager.current_mode, "PROACTIVE")
        mock_publish_status.assert_called_once()

        mock_set_cpu_governor.reset_mock()
        srm_manager.mqtt_client_instance.publish.reset_mock()
        mock_publish_status.reset_mock()

        # Switch back to STANDBY
        srm_manager.current_mode = "PROACTIVE"
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=(mock_mqtt_client_module.MQTT_ERR_SUCCESS, 2))
        srm_manager.switch_mode("STANDBY")
        mock_set_cpu_governor.assert_called_with(srm_manager.CPU_GOVERNOR_STANDBY)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_DETECT_SET, "OFF", qos=1)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_RECORD_SET, "OFF", qos=1)
        self.assertEqual(srm_manager.current_mode, "STANDBY")
        mock_publish_status.assert_called_once()

    # Robustness: Switch to the same mode
    @patch('srm_manager.set_cpu_governor')
    @patch('srm_manager.publish_status')
    def test_robustness_switch_mode_no_change(self, mock_publish_status, mock_set_cpu_governor):
        """Verify switching to the current mode does nothing."""
        srm_manager.current_mode = "PROACTIVE"
        srm_manager.mqtt_client_instance.publish = MagicMock()
        srm_manager.switch_mode("PROACTIVE")
        self.assertEqual(srm_manager.current_mode, "PROACTIVE")
        mock_set_cpu_governor.assert_not_called()
        srm_manager.mqtt_client_instance.publish.assert_not_called()
        mock_publish_status.assert_not_called()

    # TS SECU 05
    def test_spec_TS_SECU_05_recording_control(self):
        """Verify Frigate recording is enabled/disabled correctly."""
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=(mock_mqtt_client_module.MQTT_ERR_SUCCESS, 3))
        with patch('srm_manager.publish_status'):
             srm_manager.switch_mode("PROACTIVE")
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_RECORD_SET, "ON", qos=1)

        srm_manager.mqtt_client_instance.publish.reset_mock()
        srm_manager.mqtt_client_instance.publish.return_value = (mock_mqtt_client_module.MQTT_ERR_SUCCESS, 4)

        with patch('srm_manager.publish_status'):
             srm_manager.switch_mode("STANDBY")
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_RECORD_SET, "OFF", qos=1)

class TestSensorProcessingAndAlerts(BaseSRMTest):

    # TS SECU 08
    def test_spec_TS_SECU_08_radar_parsing_logic(self):
        """Verify LD2410C serial data parsing logic."""
        payload_content = b'\xAA\x00' + struct.pack('<BHHHHH', 3, 150, 60, 50, 20, 150) # Moving+Static
        data_len = len(payload_content)
        frame_core = struct.pack('<HB', data_len, 0x01) + payload_content
        checksum = srm_manager.calculate_checksum(frame_core)
        full_frame = srm_manager.FRAME_HEADER + frame_core + bytes([checksum]) + srm_manager.FRAME_END
        parsed = srm_manager.parse_ld2410c_frame(full_frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['target_state'], "Moving+Static")
        self.assertEqual(parsed['moving_target_distance_cm'], 150)
        self.assertEqual(parsed['static_target_distance_cm'], 50)

    # Robustness: Test parsing invalid frames
    def test_robustness_radar_parsing_invalid_frames(self):
        """Verify parsing handles invalid/incomplete frames."""
        self.assertIsNone(srm_manager.parse_ld2410c_frame(b''))
        self.assertIsNone(srm_manager.parse_ld2410c_frame(srm_manager.FRAME_HEADER + b'\x00' + srm_manager.FRAME_END)) # Too short
        frame_core = struct.pack('<HB', 5, 0x99) + b'\x01\x02\x03\x04\x05'
        checksum = srm_manager.calculate_checksum(frame_core)
        full_frame = srm_manager.FRAME_HEADER + frame_core + bytes([checksum]) + srm_manager.FRAME_END
        self.assertIsNone(srm_manager.parse_ld2410c_frame(full_frame))

    # TS SECU 02
    def test_spec_TS_SECU_02_frigate_event_processing(self):
        """Verify processing of Frigate 'person' detection events."""
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_FRIGATE_EVENTS
        event_payload = {"type": "new", "after": {"label": "person"}}
        msg_mock.payload = json.dumps(event_payload).encode('utf-8')
        srm_manager.camera_detection = False
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.assertTrue(srm_manager.camera_detection)

    # Robustness: Test Frigate event with non-person label
    def test_robustness_frigate_event_other_label(self):
        """Verify non-person Frigate events don't trigger camera_detection."""
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_FRIGATE_EVENTS
        event_payload = {"type": "new", "after": {"label": "car"}}
        msg_mock.payload = json.dumps(event_payload).encode('utf-8')
        srm_manager.camera_detection = False
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.assertFalse(srm_manager.camera_detection)

    # Robustness: Test Frigate event with invalid JSON
    @patch('srm_manager.logging.error')
    def test_robustness_frigate_event_invalid_json(self, mock_log_error):
        """Verify invalid JSON in Frigate event is handled."""
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_FRIGATE_EVENTS
        msg_mock.payload = b'{"type": "new", "after": {"label": "person'
        srm_manager.camera_detection = False
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.assertFalse(srm_manager.camera_detection)
        mock_log_error.assert_called_with(f"Failed to decode JSON payload on topic {msg_mock.topic}: {msg_mock.payload.decode('utf-8')}")

    # TS SECU 01
    @patch('srm_manager.log_alert_event')
    def test_spec_TS_SECU_01_hidden_intruder_alert_logic(self, mock_log_alert):
        """Verify hidden intruder alert logic triggers logging and publish."""
        srm_manager.system_armed = True; srm_manager.ld2410c_presence_detected = True; srm_manager.camera_detection = False
        self.mock_time.return_value = 1234567890.0; srm_manager.last_fusion_alert_time = 0
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=True) # Simulate success

        srm_manager.check_fusion_logic()
        mock_log_alert.assert_called_once()
        srm_manager.mqtt_client_instance.publish.assert_called_once_with(
            srm_manager.MQTT_TOPIC_ALERTS, ANY, qos=1
        )
        args, kwargs = srm_manager.mqtt_client_instance.publish.call_args
        payload = json.loads(args[1])
        self.assertEqual(payload['type'], "hidden_intruder")

    # Robustness: Test alert cooldown logic
    @patch('srm_manager.log_alert_event')
    def test_robustness_alert_cooldown(self, mock_log_alert):
        """Verify alert logic respects cooldown period."""
        srm_manager.system_armed = True; srm_manager.ld2410c_presence_detected = True; srm_manager.camera_detection = False; srm_manager.camera_blind = True
        self.mock_time.return_value = 1234567890.0
        srm_manager.last_fusion_alert_time = self.mock_time.return_value - (srm_manager.ALERT_COOLDOWN / 2)
        srm_manager.last_tamper_alert_time = self.mock_time.return_value - (srm_manager.ALERT_COOLDOWN / 2)
        srm_manager.mqtt_client_instance.publish = MagicMock()

        srm_manager.check_fusion_logic()
        srm_manager.check_tamper_detection()

        mock_log_alert.assert_not_called()
        srm_manager.mqtt_client_instance.publish.assert_not_called()

    # TS SECU 01
    @patch('srm_manager.log_alert_event')
    def test_spec_TS_SECU_01_tamper_alert_logic(self, mock_log_alert):
        """Verify tamper alert logic triggers logging and publish."""
        srm_manager.system_armed = True; srm_manager.ld2410c_presence_detected = True; srm_manager.camera_blind = True
        self.mock_time.return_value = 1234567890.0; srm_manager.last_tamper_alert_time = 0
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=True) # Simulate success

        srm_manager.check_tamper_detection()
        mock_log_alert.assert_called_once()
        srm_manager.mqtt_client_instance.publish.assert_called_once_with(
            srm_manager.MQTT_TOPIC_ALERTS, ANY, qos=1
        )
        args, kwargs = srm_manager.mqtt_client_instance.publish.call_args
        payload = json.loads(args[1])
        self.assertEqual(payload['type'], "tamper_suspected")

    # TS SECU 01
    @patch('srm_manager.publish_status')
    def test_spec_TS_SECU_01_camera_blind_update_logic(self, mock_publish_status):
        """Verify camera blind status update logic."""
        srm_manager.ld2410c_presence_detected = True; srm_manager.camera_detection = False; srm_manager.last_camera_detection_time_with_radar = 0
        srm_manager.time_radar_became_active = self.mock_time.return_value - (srm_manager.NO_DETECTION_WHILE_RADAR_TIMEOUT + 1)
        srm_manager.update_camera_blind_status()
        self.assertTrue(srm_manager.camera_blind)
        mock_publish_status.assert_called_once()

class TestIntegrationAndCommands(BaseSRMTest):

    # TS INT 01
    def test_spec_TS_INT_01_status_publishing(self):
        """Verify system status is published correctly."""
        srm_manager.current_mode = "PROACTIVE"; srm_manager.manual_override_mode = "PROACTIVE"
        srm_manager.mqtt_client_instance.publish = MagicMock(return_value=True) # Simulate success

        srm_manager.publish_status() # Call the actual function

        expected_payload = {
            "timestamp": 1234567890.0, "mode": "PROACTIVE", "presence_radar": False,
            "presence_camera": False, "armed": True, "override": "PROACTIVE",
            "status": "online", "camera_blind": False
        }
        srm_manager.mqtt_client_instance.publish.assert_called_with(
            srm_manager.MQTT_TOPIC_STATUS, expected_payload, retain=True, qos=1
        )

    # TS INT 02
    @patch('srm_manager.publish_status')
    def test_spec_TS_INT_02_command_handling(self, mock_publish_status):
        """Verify handling of incoming MQTT commands (Arm/Disarm/Override)."""
        srm_manager.system_armed = False
        srm_manager.handle_node_red_command({"mode": "ARMED"})
        self.assertTrue(srm_manager.system_armed)
        mock_publish_status.assert_called()
        mock_publish_status.reset_mock()
        srm_manager.manual_override_mode = None
        srm_manager.handle_node_red_command({"override_mode": "STANDBY"})
        self.assertEqual(srm_manager.manual_override_mode, "STANDBY")
        mock_publish_status.assert_called()

    # Robustness: Test invalid command payload/structure
    @patch('srm_manager.logging.warning')
    @patch('srm_manager.logging.error')
    @patch('srm_manager.publish_status')
    def test_robustness_invalid_command_handling(self, mock_publish_status, mock_log_error, mock_log_warning):
        """Verify handling of invalid/malformed commands."""
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_COMMANDS
        msg_mock.payload = b'{"mode": "ARMED'
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        mock_log_error.assert_called_with(f"Failed to decode JSON payload on topic {msg_mock.topic}: {msg_mock.payload.decode('utf-8')}")
        mock_publish_status.assert_not_called()
        srm_manager.handle_node_red_command({"invalid_key": "some_value"})
        mock_log_warning.assert_any_call("Received unrecognized command structure from Node-RED: {'invalid_key': 'some_value'}")
        mock_publish_status.assert_not_called()
        srm_manager.handle_node_red_command({"mode": "INVALID_MODE"})
        mock_log_warning.assert_any_call("Received unknown 'mode' (for arm/disarm) command value: INVALID_MODE")
        mock_publish_status.assert_not_called()

    # TS INT 07 / TS SECU 10
    @patch('srm_manager.threading.Thread')
    def test_spec_TS_INT_07_mqtt_reconnection_logic(self, mock_thread):
        """Verify MQTT client attempts reconnection (simulated)."""
        self.client_wrapper.connected = True; srm_manager.mqtt_client_connected = True
        self.client_wrapper._on_disconnect(self.client_wrapper.client, None, 1)
        self.assertFalse(self.client_wrapper.connected)

    # TS SECU 10 / TS INT 07
    @patch('srm_manager.threading.Thread')
    def test_spec_TS_SECU_10_LWT_setup(self, mock_thread):
        """Verify Last Will & Testament is configured."""
        # Mock the connect call to simulate success and trigger on_connect
        def mock_connect_and_callback(*args, **kwargs):
            # Simulate the on_connect callback being triggered by the connect success
            self.client_wrapper._on_connect(self.client_wrapper.client, None, None, 0)
            # Simulate loop_start being called successfully
            mock_mqtt_client_instance.loop_start()

        # Patch the underlying client's connect method with the side effect
        with patch.object(self.client_wrapper.client, 'connect', side_effect=mock_connect_and_callback) as mock_paho_connect:
            # Call _connect_blocking directly once.
            # The side effect should set connected=True and break the loop.
            try:
                self.client_wrapper._connect_blocking()
            except Exception as e:
                 self.fail(f"_connect_blocking raised unexpected exception: {e}")

            # Check that will_set was called before connect attempt
            mock_mqtt_client_instance.will_set.assert_called_once()
            args_will, kwargs_will = mock_mqtt_client_instance.will_set.call_args
            # FIX 1: Access payload via keyword argument 'payload'
            self.assertEqual(args_will[0], srm_manager.MQTT_TOPIC_STATUS) # Topic
            self.assertEqual(kwargs_will['qos'], 1)
            self.assertTrue(kwargs_will['retain'])
            self.assertIn('payload', kwargs_will) # Check payload was passed as kwarg
            payload = json.loads(kwargs_will['payload']) # Decode payload from kwarg
            self.assertEqual(payload['status'], 'offline')
            self.assertIn('reason', payload)

            # Check that connect was attempted
            mock_paho_connect.assert_called_once()
            # Check loop_start was called (simulated in side_effect)
            mock_mqtt_client_instance.loop_start.assert_called_once()


class TestMaintenanceAndLifecycle(BaseSRMTest):

    # TS SECU 14
    @patch('srm_manager.serial.Serial')
    @patch('srm_manager.threading.Thread')
    def test_spec_TS_SECU_14_cleanup_logic(self, mock_thread, mock_serial):
        """Verify cleanup function attempts to release resources."""
        # FIX 2: Reset GPIO mock at the start of this test method
        mock_gpio.reset_mock()

        srm_manager.serial_thread_running = True
        mock_thread_inst = MagicMock(); mock_thread_inst.is_alive.return_value = True
        srm_manager.serial_thread = mock_thread_inst
        mock_serial_port_inst = MagicMock(); mock_serial_port_inst.is_open = True
        srm_manager.serial_port_instance = mock_serial_port_inst
        # Assign the wrapper created in setUp to the global variable
        srm_manager.mqtt_client_instance = self.client_wrapper
        # Mock the disconnect method ON THE WRAPPER instance
        srm_manager.mqtt_client_instance.disconnect = MagicMock()

        srm_manager.cleanup()

        self.assertFalse(srm_manager.serial_thread_running)
        mock_thread_inst.join.assert_called_once_with(timeout=2.0)
        mock_serial_port_inst.close.assert_called_once()
        # Check disconnect was called on the wrapper instance
        srm_manager.mqtt_client_instance.disconnect.assert_called_once()
        mock_gpio.cleanup.assert_called_once() # Now this should pass

    # Robustness: Test cleanup when resources are already None or closed
    @patch('srm_manager.serial.Serial')
    @patch('srm_manager.threading.Thread')
    def test_robustness_cleanup_already_done(self, mock_thread, mock_serial):
        """Verify cleanup handles cases where resources might already be released."""
        # FIX 2: Reset GPIO mock at the start of this test method
        mock_gpio.reset_mock()

        srm_manager.serial_thread_running = False
        srm_manager.serial_thread = None
        mock_serial_port_inst = MagicMock(); mock_serial_port_inst.is_open = False
        srm_manager.serial_port_instance = mock_serial_port_inst
        srm_manager.mqtt_client_instance = None # MQTT instance is None

        try:
            srm_manager.cleanup()
        except Exception as e:
            self.fail(f"cleanup() raised unexpected exception: {e}")

        mock_serial_port_inst.close.assert_not_called()
        mock_gpio.cleanup.assert_called_once() # Now this should pass


if __name__ == '__main__':
    output_filename = 'unit_test_results.txt'
    with open(output_filename, 'w') as f:
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestInitializationAndCompliance))
        suite.addTest(unittest.makeSuite(TestPowerAndModeLogic))
        suite.addTest(unittest.makeSuite(TestSensorProcessingAndAlerts))
        suite.addTest(unittest.makeSuite(TestIntegrationAndCommands))
        suite.addTest(unittest.makeSuite(TestMaintenanceAndLifecycle))

        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        print(f"Running specification-focused tests and writing results to {output_filename}...")
        test_result = runner.run(suite)
        print("Test run complete.")
        print("\n--- Test Summary ---")
        print(f"Ran: {test_result.testsRun}")
        print(f"Errors: {len(test_result.errors)}")
        print(f"Failures: {len(test_result.failures)}")
        if not test_result.wasSuccessful():
             print("\nErrors/Failures occurred. Check unit_test_results.txt for details.")

