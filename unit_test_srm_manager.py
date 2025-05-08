# test_srm_manager.py
import unittest
from unittest.mock import patch, MagicMock, mock_open, call, ANY
import sys
import os
import time
import json
import logging
import struct

# Mock RPi.GPIO and serial before importing srm_manager
mock_gpio = MagicMock()
sys.modules['RPi.GPIO'] = mock_gpio
sys.modules['RPi'] = MagicMock(GPIO=mock_gpio)

mock_serial = MagicMock()
sys.modules['serial'] = mock_serial

# Mock paho.mqtt.client
mock_mqtt_client_module = MagicMock()
mock_mqtt_client_instance = MagicMock()
mock_mqtt_client_module.Client.return_value = mock_mqtt_client_instance
mock_mqtt_client_module.CallbackAPIVersion.VERSION1 = 1
mock_mqtt_client_module.MQTT_ERR_SUCCESS = 0
mock_mqtt_client_module.MQTT_ERR_NO_CONN = 1
mock_mqtt_client_module.connack_string = MagicMock(return_value="Connection Accepted")
mock_mqtt_client_module.error_string = MagicMock(return_value="Some MQTT Error")

sys.modules['paho.mqtt.client'] = mock_mqtt_client_module
sys.modules['paho.mqtt'] = MagicMock(client=mock_mqtt_client_module)
sys.modules['paho'] = MagicMock(mqtt=sys.modules['paho.mqtt'])

import srm_manager

def reset_logging_handlers():
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

class TestSRMManagerInitializationAndGlobals(unittest.TestCase):
    _gpio_mock_preserved = False

    @patch('srm_manager.logging.basicConfig')
    @patch('srm_manager.os.makedirs')
    @patch('srm_manager.sys.exit')
    def setUp(self, mock_sys_exit, mock_makedirs, mock_basicConfig):
        if not TestSRMManagerInitializationAndGlobals._gpio_mock_preserved:
            TestSRMManagerInitializationAndGlobals._gpio_mock_preserved = True

        mock_serial.reset_mock()
        mock_mqtt_client_module.reset_mock()
        mock_mqtt_client_instance.reset_mock()
        mock_mqtt_client_module.Client.return_value = mock_mqtt_client_instance
        mock_makedirs.reset_mock()
        mock_basicConfig.reset_mock()
        mock_sys_exit.reset_mock()

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

        self.patcher_time = patch('srm_manager.time.time', return_value=1234567890.0)
        self.mock_time = self.patcher_time.start()
        self.patcher_monotonic = patch('srm_manager.time.monotonic', return_value=1000.0)
        self.mock_monotonic = self.patcher_monotonic.start()
        self.patcher_sleep = patch('srm_manager.time.sleep', return_value=None)
        self.mock_sleep = self.patcher_sleep.start()

        if srm_manager.mqtt_client_instance:
             srm_manager.mqtt_client_instance.client = mock_mqtt_client_instance

    def tearDown(self):
        self.patcher_time.stop()
        self.patcher_monotonic.stop()
        self.patcher_sleep.stop()

    @patch('srm_manager.os.path.exists', return_value=False)
    @patch('srm_manager.os.makedirs')
    @patch('srm_manager.logging.FileHandler')
    @patch('srm_manager.logging.getLogger')
    def test_logging_setup_creates_directories(self, mock_getLogger, mock_file_handler, mock_makedirs, mock_path_exists):
        mock_logger_instance = MagicMock()
        mock_getLogger.return_value = mock_logger_instance
        srm_manager.FUSION_ALERT_LOG_FILE = "/tmp/test_fusion.log"
        srm_manager.setup_fusion_logger()
        mock_makedirs.assert_any_call(os.path.dirname(srm_manager.FUSION_ALERT_LOG_FILE), exist_ok=True)
        mock_getLogger.assert_called_with('FusionTamperLogger')
        mock_file_handler.assert_any_call(srm_manager.FUSION_ALERT_LOG_FILE, mode='a')
        self.assertIs(srm_manager.fusion_logger, mock_logger_instance)
        mock_logger_instance.info.assert_called_with("Fusion/Tamper alert logger initialized.")

    def test_gpio_setup_success(self):
        mock_gpio.setmode.assert_called_with(mock_gpio.BCM)
        mock_gpio.setup.assert_called_with(srm_manager.LD2410C_OUT_PIN, mock_gpio.IN, pull_up_down=mock_gpio.PUD_DOWN)
        mock_gpio.setwarnings.assert_called_with(False)

class TestHelperFunctions(unittest.TestCase):
    def setUp(self):
        self.patcher_os_system = patch('srm_manager.os.system')
        self.mock_os_system = self.patcher_os_system.start()
        self.patcher_sys_platform = patch('srm_manager.sys.platform', 'linux') # Assume Linux
        self.mock_sys_platform = self.patcher_sys_platform.start()
        self.patcher_logging_warning = patch('srm_manager.logging.warning')
        self.mock_logging_warning = self.patcher_logging_warning.start()
        self.patcher_logging_info = patch('srm_manager.logging.info')
        self.mock_logging_info = self.patcher_logging_info.start()
        if hasattr(srm_manager.set_cpu_governor, 'cmd_exists'):
            delattr(srm_manager.set_cpu_governor, 'cmd_exists')

    def tearDown(self):
        self.patcher_os_system.stop()
        self.patcher_sys_platform.stop()
        self.patcher_logging_warning.stop()
        self.patcher_logging_info.stop()

    def test_set_cpu_governor_linux_cmd_exists(self):
        self.mock_os_system.side_effect = [0, 0]
        srm_manager.set_cpu_governor("ondemand")
        self.mock_os_system.assert_any_call("command -v cpufreq-set > /dev/null")
        self.mock_os_system.assert_any_call("sudo cpufreq-set -g ondemand")
        self.mock_logging_info.assert_any_call("Attempting to set CPU governor to: ondemand")

    def test_set_cpu_governor_linux_cmd_not_exists(self):
        self.mock_os_system.return_value = 1
        srm_manager.set_cpu_governor("ondemand")
        self.mock_os_system.assert_called_once_with("command -v cpufreq-set > /dev/null")
        self.mock_logging_warning.assert_called_with("`cpufreq-set` command not found. Install 'cpufrequtils'. Cannot set CPU governor.")

    def test_set_cpu_governor_not_linux(self):
        with patch('srm_manager.sys.platform', 'darwin'):
            with patch('srm_manager.logging.debug') as mock_debug:
                srm_manager.set_cpu_governor("ondemand")
                mock_debug.assert_called_with("CPU governor setting skipped (not on Linux).")
                self.mock_os_system.assert_not_called()

    def test_set_cpu_governor_command_fails(self):
        self.mock_os_system.side_effect = [0, 1]
        srm_manager.set_cpu_governor("powersave")
        self.mock_os_system.assert_any_call("sudo cpufreq-set -g powersave")
        self.mock_logging_warning.assert_called_with("Failed to run `cpufreq-set -g powersave` (exit code 1). Check permissions or if governor 'powersave' is supported.")


class TestMQTTClientWrapper(unittest.TestCase):

    def setUp(self):
        mock_mqtt_client_instance.reset_mock()
        mock_mqtt_client_module.Client.return_value = mock_mqtt_client_instance

        srm_manager.mqtt_client_connected = False
        srm_manager.current_mode = "STANDBY"
        srm_manager.ld2410c_presence_detected = False
        srm_manager.camera_detection = False
        srm_manager.system_armed = True
        srm_manager.manual_override_mode = None
        srm_manager.camera_blind = False

        self.mock_command_callback = MagicMock()
        self.client_wrapper = srm_manager.MQTTClientWrapper(
            "localhost", 1883, "test_client", None, None, self.mock_command_callback
        )
        self.client_wrapper.client = mock_mqtt_client_instance

        self.patcher_time = patch('srm_manager.time.time', return_value=1234567890.0)
        self.mock_time = self.patcher_time.start()
        self.patcher_sleep = patch('srm_manager.time.sleep', return_value=None)
        self.mock_sleep = self.patcher_sleep.start()
        self.patcher_publish_status = patch('srm_manager.publish_status')
        self.mock_publish_status = self.patcher_publish_status.start()
        self.patcher_publish_ld2410c_status = patch('srm_manager.publish_ld2410c_status')
        self.mock_publish_ld2410c_status = self.patcher_publish_ld2410c_status.start()

    def tearDown(self):
        self.patcher_time.stop()
        self.patcher_sleep.stop()
        self.patcher_publish_status.stop()
        self.patcher_publish_ld2410c_status.stop()

    def test_init(self):
        self.assertEqual(self.client_wrapper.broker, "localhost")
        self.assertIs(self.client_wrapper.client, mock_mqtt_client_instance)
        self.assertFalse(self.client_wrapper.connected)

    def test_on_connect_success(self):
        self.client_wrapper._on_connect(self.client_wrapper.client, None, None, 0)
        self.assertTrue(self.client_wrapper.connected)
        self.assertTrue(srm_manager.mqtt_client_connected)
        mock_mqtt_client_instance.subscribe.assert_any_call(srm_manager.MQTT_TOPIC_COMMANDS)
        mock_mqtt_client_instance.subscribe.assert_any_call(srm_manager.MQTT_TOPIC_FRIGATE_EVENTS)
        self.mock_publish_status.assert_called_once()
        self.mock_publish_ld2410c_status.assert_called_once()

    def test_on_connect_failure(self):
        with patch('srm_manager.logging.error') as mock_log_error:
            mock_mqtt_client_module.connack_string.return_value = "Connection Refused"
            self.client_wrapper._on_connect(self.client_wrapper.client, None, None, 5)
            self.assertFalse(self.client_wrapper.connected)
            self.assertFalse(srm_manager.mqtt_client_connected)
            mock_log_error.assert_called_with("MQTT connection failed with result code 5: Connection Refused")

    def test_on_disconnect(self):
        self.client_wrapper.connected = True
        srm_manager.mqtt_client_connected = True
        self.client_wrapper._on_disconnect(self.client_wrapper.client, None, 1)
        self.assertFalse(self.client_wrapper.connected)
        self.assertFalse(srm_manager.mqtt_client_connected)

    def test_on_message_command(self):
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_COMMANDS
        command_payload = {"mode": "ARMED"}
        msg_mock.payload = json.dumps(command_payload).encode('utf-8')
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.mock_command_callback.assert_called_once_with(command_payload)

    def test_on_message_frigate_person_new(self):
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_FRIGATE_EVENTS
        event_payload = {"type": "new", "after": {"label": "person"}}
        msg_mock.payload = json.dumps(event_payload).encode('utf-8')
        srm_manager.camera_detection = False
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.assertTrue(srm_manager.camera_detection)
        self.assertGreater(srm_manager.last_camera_detection_time, 0)

    def test_on_message_frigate_person_end(self):
        msg_mock = MagicMock()
        msg_mock.topic = srm_manager.MQTT_TOPIC_FRIGATE_EVENTS
        event_payload = {"type": "end", "before": {"label": "person"}}
        msg_mock.payload = json.dumps(event_payload).encode('utf-8')
        srm_manager.camera_detection = True
        self.client_wrapper._on_message(self.client_wrapper.client, None, msg_mock)
        self.assertFalse(srm_manager.camera_detection)

    def test_publish_success(self):
        self.client_wrapper.connected = True
        mock_mqtt_client_instance.publish.return_value = (srm_manager.mqtt.MQTT_ERR_SUCCESS, 123)
        payload = {"data": "value"}
        result = self.client_wrapper.publish("a/topic", payload, retain=True, qos=1)
        self.assertTrue(result)
        mock_mqtt_client_instance.publish.assert_called_once_with("a/topic", json.dumps(payload), qos=1, retain=True)

    def test_publish_not_connected(self):
        self.client_wrapper.connected = False
        result = self.client_wrapper.publish("a/topic", {"data": "value"})
        self.assertFalse(result)
        mock_mqtt_client_instance.publish.assert_not_called()

    @patch('srm_manager.threading.Thread')
    def test_connect_async_starts_thread(self, mock_thread_constructor):
        mock_thread_instance = MagicMock()
        mock_thread_constructor.return_value = mock_thread_instance
        self.client_wrapper.connect_async()
        mock_thread_constructor.assert_called_once_with(target=self.client_wrapper._connect_blocking, name="MQTTConnectThread", daemon=True)
        mock_thread_instance.start.assert_called_once()

    def test_disconnect_publishes_offline_status(self):
        self.client_wrapper.connected = True
        srm_manager.mqtt_client_connected = True
        mock_mqtt_client_instance.is_connected.return_value = True

        expected_lwt_payload = {
            "status": "offline", "reason": "shutdown", "mode": srm_manager.current_mode,
            "presence_radar": srm_manager.ld2410c_presence_detected,
            "presence_camera": srm_manager.camera_detection,
            "armed": srm_manager.system_armed,
            "override": srm_manager.manual_override_mode,
            "camera_blind": srm_manager.camera_blind
        }
        self.client_wrapper.publish = MagicMock()

        self.client_wrapper.disconnect()

        self.client_wrapper.publish.assert_called_once_with(
            srm_manager.MQTT_TOPIC_STATUS,
            expected_lwt_payload,
            retain=True, qos=1
        )
        mock_mqtt_client_instance.loop_stop.assert_called_once()
        mock_mqtt_client_instance.disconnect.assert_called_once()
        self.assertFalse(self.client_wrapper.connected)
        self.assertFalse(srm_manager.mqtt_client_connected)


class TestLD2410CSerialProcessing(unittest.TestCase):
    def setUp(self):
        self.patcher_time = patch('srm_manager.time.time', return_value=1234567890.0)
        self.mock_time = self.patcher_time.start()
        srm_manager.mqtt_client_instance = MagicMock()
        srm_manager.mqtt_client_connected = True

    def tearDown(self):
        self.patcher_time.stop()
        srm_manager.mqtt_client_instance = None

    def test_calculate_checksum(self):
        self.assertEqual(srm_manager.calculate_checksum(b'\x01\x02\x03'), 6)
        self.assertEqual(srm_manager.calculate_checksum(b'\xFF\x01'), 0)

    def test_parse_ld2410c_frame_valid_target_report(self):
        payload_content = b'\xAA\x00' + struct.pack('<BHHHHH', 1, 100, 50, 0, 0, 100)
        data_len = len(payload_content)
        frame_core = struct.pack('<HB', data_len, 0x01) + payload_content
        checksum = srm_manager.calculate_checksum(frame_core)
        full_frame = srm_manager.FRAME_HEADER + frame_core + bytes([checksum]) + srm_manager.FRAME_END

        parsed = srm_manager.parse_ld2410c_frame(full_frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['target_state'], "Moving")
        self.assertEqual(parsed['moving_target_distance_cm'], 100)

    def test_parse_ld2410c_frame_invalid_checksum(self):
        payload_content = b'\xAA\x00' + struct.pack('<BHHHHH', 1, 100, 50, 0, 0, 100)
        data_len = len(payload_content)
        frame_core = struct.pack('<HB', data_len, 0x01) + payload_content
        checksum = srm_manager.calculate_checksum(frame_core)
        full_frame = srm_manager.FRAME_HEADER + frame_core + bytes([checksum + 1]) + srm_manager.FRAME_END

        with patch('srm_manager.logging.warning') as mock_log_warn:
            parsed = srm_manager.parse_ld2410c_frame(full_frame)
            self.assertIsNone(parsed)
            mock_log_warn.assert_called_with(f"LD2410C Checksum mismatch. Expected {checksum+1:#04x}, calculated {checksum:#04x}")

    def test_publish_ld2410c_details(self):
        details_payload = {"key": "value"}
        srm_manager.publish_ld2410c_details(details_payload)
        srm_manager.mqtt_client_instance.publish.assert_called_once_with(
            srm_manager.MQTT_TOPIC_LD2410C_DETAILS, details_payload, retain=False, qos=0
        )

class TestModeManagementAndStatus(unittest.TestCase):
    def setUp(self):
        srm_manager.current_mode = "STANDBY"
        srm_manager.manual_override_mode = None
        srm_manager.ld2410c_presence_detected = False
        srm_manager.camera_detection = False
        srm_manager.system_armed = True
        srm_manager.camera_blind = False
        srm_manager.mqtt_client_instance = MagicMock()
        srm_manager.mqtt_client_connected = True

        self.patcher_time = patch('srm_manager.time.time', return_value=1234567890.0)
        self.mock_time = self.patcher_time.start()
        self.patcher_monotonic = patch('srm_manager.time.monotonic', return_value=1000.0)
        self.mock_monotonic = self.patcher_monotonic.start()
        self.patcher_set_cpu = patch('srm_manager.set_cpu_governor')
        self.mock_set_cpu = self.patcher_set_cpu.start()
        # DO NOT patch publish_status here if testing publish_status itself

    def tearDown(self):
        self.patcher_time.stop()
        self.patcher_monotonic.stop()
        self.patcher_set_cpu.stop()
        srm_manager.mqtt_client_instance = None

    def test_determine_target_mode_auto_no_presence(self):
        srm_manager.ld2410c_presence_detected = False
        srm_manager.manual_override_mode = None
        self.assertEqual(srm_manager.determine_target_mode(), "STANDBY")

    def test_determine_target_mode_auto_with_presence(self):
        srm_manager.ld2410c_presence_detected = True
        srm_manager.manual_override_mode = None
        self.assertEqual(srm_manager.determine_target_mode(), "PROACTIVE")

    @patch('srm_manager.publish_status') # Patch locally for this test only
    def test_switch_mode_to_proactive(self, mock_publish_status_local):
        srm_manager.current_mode = "STANDBY"
        srm_manager.switch_mode("PROACTIVE")

        self.assertEqual(srm_manager.current_mode, "PROACTIVE")
        self.mock_set_cpu.assert_called_once_with(srm_manager.CPU_GOVERNOR_PROACTIVE)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_DETECT_SET, "ON", qos=1)
        srm_manager.mqtt_client_instance.publish.assert_any_call(srm_manager.FRIGATE_TOPIC_RECORD_SET, "ON", qos=1)
        mock_publish_status_local.assert_called_once() # Check local mock

    def test_publish_status(self):
        # Test the actual publish_status function
        srm_manager.current_mode = "TEST_MODE"
        srm_manager.mqtt_client_instance.publish.return_value = True

        # Call the real function
        srm_manager.publish_status()

        expected_payload = {
            "timestamp": 1234567890.0, "mode": "TEST_MODE",
            "presence_radar": False, "presence_camera": False, "armed": True,
            "override": None, "status": "online", "camera_blind": False
        }
        # Assert the call was made on the global mock instance
        srm_manager.mqtt_client_instance.publish.assert_called_with(
            srm_manager.MQTT_TOPIC_STATUS, expected_payload, retain=True, qos=1
        )
        self.assertEqual(srm_manager.last_status_publish_time, 1000.0)

    def test_publish_ld2410c_status(self):
        srm_manager.ld2410c_presence_detected = True
        expected_payload = {"timestamp": 1234567890.0, "presence": True}
        srm_manager.publish_ld2410c_status()
        srm_manager.mqtt_client_instance.publish.assert_called_with(
            srm_manager.MQTT_TOPIC_LD2410C_STATUS, expected_payload, retain=True, qos=1
        )

class TestCommandHandling(unittest.TestCase):
    def setUp(self):
        srm_manager.manual_override_mode = None
        srm_manager.system_armed = True
        self.patcher_publish_status = patch('srm_manager.publish_status')
        self.mock_publish_status = self.patcher_publish_status.start()

    def tearDown(self):
        self.patcher_publish_status.stop()

    def test_handle_command_override_proactive(self):
        srm_manager.handle_node_red_command({"override_mode": "PROACTIVE"})
        self.assertEqual(srm_manager.manual_override_mode, "PROACTIVE")
        self.mock_publish_status.assert_called_once()

    def test_handle_command_arm(self):
        srm_manager.system_armed = False
        srm_manager.handle_node_red_command({"mode": "ARMED"})
        self.assertTrue(srm_manager.system_armed)
        self.mock_publish_status.assert_called_once()

class TestSensorFusionAndTamper(unittest.TestCase):
    def setUp(self):
        srm_manager.camera_blind = False
        srm_manager.ld2410c_presence_detected = False
        srm_manager.camera_detection = False
        srm_manager.last_camera_detection_time_with_radar = 0
        srm_manager.time_radar_became_active = 0
        srm_manager.system_armed = True
        srm_manager.last_fusion_alert_time = 0
        srm_manager.last_tamper_alert_time = 0
        srm_manager.mqtt_client_instance = MagicMock()
        srm_manager.mqtt_client_connected = True
        srm_manager.fusion_logger = MagicMock()

        self.patcher_time = patch('srm_manager.time.time')
        self.mock_time = self.patcher_time.start()
        self.patcher_publish_status = patch('srm_manager.publish_status')
        self.mock_publish_status = self.patcher_publish_status.start()
        self.patcher_log_alert_event = patch('srm_manager.log_alert_event')
        self.mock_log_alert_event = self.patcher_log_alert_event.start()

    def tearDown(self):
        self.patcher_time.stop()
        self.patcher_publish_status.stop()
        self.patcher_log_alert_event.stop()
        srm_manager.mqtt_client_instance = None

    def test_update_camera_blind_trigger(self):
        srm_manager.ld2410c_presence_detected = True
        srm_manager.camera_detection = False
        srm_manager.last_camera_detection_time_with_radar = 1234567890.0 - (srm_manager.NO_DETECTION_WHILE_RADAR_TIMEOUT + 10)
        self.mock_time.return_value = 1234567890.0

        srm_manager.update_camera_blind_status()
        self.assertTrue(srm_manager.camera_blind)
        self.mock_publish_status.assert_called_once()

    def test_check_fusion_logic_hidden_intruder_alert(self):
        srm_manager.system_armed = True
        srm_manager.ld2410c_presence_detected = True
        srm_manager.camera_detection = False
        self.mock_time.return_value = 1234567890.0
        srm_manager.last_fusion_alert_time = 0

        srm_manager.check_fusion_logic()
        self.mock_log_alert_event.assert_called_once()
        srm_manager.mqtt_client_instance.publish.assert_called_once()
        args, kwargs = srm_manager.mqtt_client_instance.publish.call_args
        self.assertEqual(args[0], srm_manager.MQTT_TOPIC_ALERTS)
        payload = json.loads(args[1])
        self.assertEqual(payload['type'], "hidden_intruder")

    def test_check_tamper_detection_alert(self):
        srm_manager.system_armed = True
        srm_manager.ld2410c_presence_detected = True
        srm_manager.camera_blind = True
        self.mock_time.return_value = 1234567890.0
        srm_manager.last_tamper_alert_time = 0

        srm_manager.check_tamper_detection()
        self.mock_log_alert_event.assert_called_once()
        srm_manager.mqtt_client_instance.publish.assert_called_once()
        args, kwargs = srm_manager.mqtt_client_instance.publish.call_args
        self.assertEqual(args[0], srm_manager.MQTT_TOPIC_ALERTS)
        payload = json.loads(args[1])
        self.assertEqual(payload['type'], "tamper_suspected")

class TestMainAndLifecycle(unittest.TestCase):

    @patch('srm_manager.main_loop')
    @patch('srm_manager.cleanup')
    @patch('srm_manager.MQTTClientWrapper')
    @patch('srm_manager.serial.Serial')
    @patch('srm_manager.threading.Thread')
    @patch('srm_manager.setup_fusion_logger')
    @patch('srm_manager.publish_status')
    @patch('srm_manager.publish_ld2410c_status')
    @patch('srm_manager.time.sleep', return_value=None)
    def test_main_execution_flow_simulation(self, mock_sleep, mock_pub_ld_stat, mock_pub_stat,
                                 mock_setup_fusion, mock_thread_constructor, mock_serial_constructor,
                                 mock_mqtt_wrapper_constructor, mock_cleanup, mock_main_loop):

        mock_serial_instance = MagicMock()
        mock_serial_constructor.return_value = mock_serial_instance
        mock_thread_instance = MagicMock()
        mock_thread_constructor.return_value = mock_thread_instance
        mock_mqtt_wrapper_instance = MagicMock()
        mock_mqtt_wrapper_constructor.return_value = mock_mqtt_wrapper_instance

        srm_manager.ENABLE_SERIAL_DEBUG = True
        srm_manager.mqtt_client_connected = True

        # Simulate the execution of the main block logic
        srm_manager.setup_fusion_logger()

        if srm_manager.ENABLE_SERIAL_DEBUG:
            try:
                srm_manager.serial_port_instance = mock_serial_constructor(srm_manager.SERIAL_PORT, srm_manager.BAUD_RATE, timeout=0.1)
                srm_manager.serial_thread_running = True
                srm_manager.serial_thread = mock_thread_constructor(target=srm_manager.serial_reader_thread_func, name=ANY, daemon=True)
                srm_manager.serial_thread.start()
            except Exception: pass

        srm_manager.mqtt_client_instance = mock_mqtt_wrapper_constructor(ANY, ANY, ANY, ANY, ANY, ANY)
        srm_manager.mqtt_client_instance.connect_async()

        if srm_manager.mqtt_client_connected:
            srm_manager.publish_status()
            srm_manager.publish_ld2410c_status()

        try:
            srm_manager.main_loop()
        finally:
            srm_manager.cleanup()

        mock_setup_fusion.assert_called_once()
        if srm_manager.ENABLE_SERIAL_DEBUG:
            mock_serial_constructor.assert_called_once_with(srm_manager.SERIAL_PORT, srm_manager.BAUD_RATE, timeout=0.1)
            mock_thread_constructor.assert_called_with(target=srm_manager.serial_reader_thread_func, name=ANY, daemon=True)
            mock_thread_instance.start.assert_called_once()

        mock_mqtt_wrapper_constructor.assert_called_once()
        mock_mqtt_wrapper_instance.connect_async.assert_called_once()
        self.assertTrue(mock_pub_stat.called)
        self.assertTrue(mock_pub_ld_stat.called)
        mock_main_loop.assert_called_once()
        mock_cleanup.assert_called_once()

    @patch('srm_manager.serial.Serial')
    @patch('srm_manager.threading.Thread')
    def test_cleanup_logic(self, mock_thread_constructor, mock_serial_constructor):
        # Setup for cleanup
        srm_manager.serial_thread_running = True
        mock_thread_inst = MagicMock()
        mock_thread_inst.is_alive.return_value = True
        srm_manager.serial_thread = mock_thread_inst

        mock_serial_port_inst = MagicMock()
        mock_serial_port_inst.is_open = True
        srm_manager.serial_port_instance = mock_serial_port_inst

        mock_mqtt_client_inst_for_cleanup = MagicMock()
        srm_manager.mqtt_client_instance = mock_mqtt_client_inst_for_cleanup

        srm_manager.cleanup()

        self.assertFalse(srm_manager.serial_thread_running)
        mock_thread_inst.join.assert_called_once_with(timeout=2.0)
        mock_serial_port_inst.close.assert_called_once()
        mock_mqtt_client_inst_for_cleanup.disconnect.assert_called_once()
        mock_gpio.cleanup.assert_called_once() # Check the global mock_gpio

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSRMManagerInitializationAndGlobals))
    suite.addTest(unittest.makeSuite(TestHelperFunctions))
    suite.addTest(unittest.makeSuite(TestMQTTClientWrapper))
    suite.addTest(unittest.makeSuite(TestLD2410CSerialProcessing))
    suite.addTest(unittest.makeSuite(TestModeManagementAndStatus))
    suite.addTest(unittest.makeSuite(TestCommandHandling))
    suite.addTest(unittest.makeSuite(TestSensorFusionAndTamper))
    suite.addTest(unittest.makeSuite(TestMainAndLifecycle))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

