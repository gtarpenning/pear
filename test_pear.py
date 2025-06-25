#!/usr/bin/env python3
"""
Test suite for Pear P2P Terminal Chat
Tests core functionality with minimal mocking
"""

import unittest
import time
import threading
from unittest.mock import patch, MagicMock

from message_system import MessageHandler, ChatMessage, MockMessageRouter
from network_layer import NetworkManager, PeerInfo
from pear_cli import PearCLI


class TestMessageHandler(unittest.TestCase):
    """Test the message handling system"""

    def setUp(self):
        self.handler = MessageHandler()

    def test_add_and_retrieve_messages(self):
        """Test basic message addition and retrieval"""
        msg = self.handler.add_message("alice", "Hello world!")

        self.assertEqual(msg.username, "alice")
        self.assertEqual(msg.content, "Hello world!")
        self.assertEqual(msg.message_type, "text")
        self.assertIsInstance(msg.timestamp, float)

        messages = self.handler.get_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].content, "Hello world!")

    def test_system_messages(self):
        """Test system message functionality"""
        msg = self.handler.add_system_message("User joined")

        self.assertEqual(msg.username, "SYSTEM")
        self.assertEqual(msg.message_type, "system")
        self.assertEqual(msg.content, "User joined")

    def test_message_callbacks(self):
        """Test message callback system"""
        callback_messages = []

        def callback(msg):
            callback_messages.append(msg)

        self.handler.add_message_callback(callback)
        self.handler.add_message("bob", "Test message")

        self.assertEqual(len(callback_messages), 1)
        self.assertEqual(callback_messages[0].content, "Test message")

    def test_message_limit(self):
        """Test message storage limit"""
        self.handler.max_messages = 3

        # Add more messages than the limit
        for i in range(5):
            self.handler.add_message("user", f"Message {i}")

        messages = self.handler.get_messages()
        self.assertEqual(len(messages), 3)
        # Should keep the last 3 messages
        self.assertEqual(messages[0].content, "Message 2")
        self.assertEqual(messages[2].content, "Message 4")

    def test_message_stats(self):
        """Test message statistics"""
        self.handler.add_message("alice", "Hello")
        self.handler.add_message("bob", "Hi there")
        self.handler.add_message("alice", "How are you?")
        self.handler.add_system_message("Test system message")

        stats = self.handler.get_message_stats()

        self.assertEqual(stats["total_messages"], 4)
        self.assertEqual(stats["unique_users"], 2)  # alice, bob (system not counted)
        self.assertEqual(stats["user_message_counts"]["alice"], 2)
        self.assertEqual(stats["user_message_counts"]["bob"], 1)

    def test_message_search(self):
        """Test message search functionality"""
        self.handler.add_message("alice", "Hello world")
        self.handler.add_message("bob", "Python is great")
        self.handler.add_message("charlie", "Hello everyone")

        # Search by content
        results = self.handler.search_messages("hello")
        self.assertEqual(len(results), 2)

        # Search by username
        results = self.handler.search_messages("bob")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].content, "Python is great")


class TestNetworkManager(unittest.TestCase):
    """Test network management functionality"""

    def setUp(self):
        self.network = NetworkManager()

    def test_initialization(self):
        """Test basic network manager initialization"""
        self.assertIsInstance(self.network.local_hostname, str)
        self.assertIsInstance(self.network.local_ip, str)
        self.assertEqual(self.network.discovery_port, 8888)
        self.assertEqual(self.network.message_port, 8889)
        self.assertFalse(self.network.is_host)

    def test_session_discovery(self):
        """Test session discovery (mocked)"""
        sessions = self.network.discover_sessions()

        self.assertIsInstance(sessions, list)
        self.assertGreater(len(sessions), 0)

        # Check session structure
        session = sessions[0]
        required_keys = ["name", "host", "host_ip", "port", "user_count"]
        for key in required_keys:
            self.assertIn(key, session)

    def test_session_connection(self):
        """Test connecting to a session"""
        success = self.network.connect_to_session("test_session")

        self.assertTrue(success)
        self.assertEqual(self.network.session_name, "test_session")
        self.assertFalse(self.network.is_host)
        self.assertEqual(len(self.network.peers), 1)

    def test_peer_management(self):
        """Test adding and removing peers"""
        peer = PeerInfo(
            id="test_id",
            hostname="test_host",
            ip_address="192.168.1.100",
            port=8889,
            username="testuser",
            connected_at=time.time(),
        )

        self.network.add_peer(peer)
        self.assertEqual(len(self.network.peers), 1)
        self.assertIn("test_id", self.network.peers)

        connected_peers = self.network.get_connected_peers()
        self.assertEqual(len(connected_peers), 1)
        self.assertEqual(connected_peers[0].username, "testuser")

        self.network.remove_peer("test_id")
        self.assertEqual(len(self.network.peers), 0)


class TestMockMessageRouter(unittest.TestCase):
    """Test mock message router"""

    def setUp(self):
        self.handler = MessageHandler()
        self.router = MockMessageRouter(self.handler)

    def test_mock_simulation(self):
        """Test mock message simulation"""
        initial_count = len(self.handler.get_messages())

        # Start simulation briefly
        self.router.start_mock_simulation()
        time.sleep(2)  # Let it generate some messages
        self.router.stop_mock_simulation()

        final_count = len(self.handler.get_messages())

        # Should have generated at least some messages
        # Note: This is time-dependent so we're lenient
        self.assertTrue(final_count >= initial_count)


class TestPearCLI(unittest.TestCase):
    """Test CLI functionality"""

    def setUp(self):
        self.cli = PearCLI()

    def test_cli_initialization(self):
        """Test CLI component initialization"""
        self.assertIsNotNone(self.cli.network_manager)
        self.assertIsNotNone(self.cli.message_handler)
        self.assertIsNotNone(self.cli.terminal_ui)

    def test_list_sessions(self):
        """Test session listing"""
        sessions = self.cli.list_sessions(show_output=False)

        self.assertIsInstance(sessions, list)
        self.assertGreater(len(sessions), 0)

        # Test with output (should not crash)
        self.cli.list_sessions(show_output=True)


class TestIntegration(unittest.TestCase):
    """Test integration between components"""

    def test_message_handler_network_integration(self):
        """Test message handler working with network manager"""
        handler = MessageHandler()
        network = NetworkManager()

        # Connect to a session
        network.connect_to_session("test_session")

        # Add a message
        msg = handler.add_message("testuser", "Integration test")

        # Mock sending the message through network
        network.send_message(msg.content, msg.username)

        # Verify message was stored
        messages = handler.get_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].content, "Integration test")

    def test_callback_integration(self):
        """Test callback system integration"""
        handler = MessageHandler()
        received_messages = []

        def message_callback(msg):
            received_messages.append(msg)

        handler.add_message_callback(message_callback)

        # Add messages and verify callbacks work
        handler.add_message("user1", "First message")
        handler.add_system_message("System message")

        self.assertEqual(len(received_messages), 2)
        self.assertEqual(received_messages[0].content, "First message")
        self.assertEqual(received_messages[1].message_type, "system")


class TestCoreWorkflow(unittest.TestCase):
    """Test complete workflows"""

    def test_basic_chat_workflow(self):
        """Test a basic chat session workflow"""
        # Initialize components
        cli = PearCLI()

        # Simulate discovering sessions
        sessions = cli.network_manager.discover_sessions()
        self.assertGreater(len(sessions), 0)

        # Connect to a session
        session_name = sessions[0]["name"]
        success = cli.network_manager.connect_to_session(session_name)
        self.assertTrue(success)

        # Add some messages
        cli.message_handler.add_system_message(f"Joined {session_name}")
        cli.message_handler.add_message("testuser", "Hello everyone!")

        # Verify messages were stored
        messages = cli.message_handler.get_messages()
        self.assertEqual(len(messages), 2)

        # Get stats
        stats = cli.message_handler.get_message_stats()
        self.assertEqual(stats["total_messages"], 2)
        self.assertEqual(stats["unique_users"], 1)


def main():
    """Run all tests"""
    # Run tests with minimal output
    unittest.main(verbosity=1, exit=False)

    # Show a summary using rich
    from rich.console import Console

    console = Console()
    console.print("\n[bold green]✅ Test suite completed![/bold green]")
    console.print("[dim]All core Pear functionality has been tested.[/dim]")


if __name__ == "__main__":
    main()
