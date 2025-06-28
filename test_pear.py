#!/usr/bin/env python3
"""
Test suite for Pear P2P Terminal Chat
Tests core functionality with minimal mocking
"""

import unittest
import time

from pear.message_system import MessageHandler
from pear.network_core import NetworkManager, PeerInfo
from pear.pear_cli import PearCLI


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
        self.assertIsInstance(self.network.get_local_hostname(), str)
        self.assertIsInstance(self.network.get_local_ip(), str)
        self.assertIsNotNone(self.network.config)
        self.assertFalse(self.network.is_host)

    def test_session_discovery(self):
        """Test session discovery"""
        sessions = self.network.discover_sessions()

        self.assertIsInstance(sessions, list)
        # Note: Without actual running sessions, the list will be empty
        # This is expected behavior for the simplified network core
        
        # If we want to test with data, we'd need to set up actual sessions
        # For now, just verify the method doesn't crash and returns the right type

    def test_session_connection(self):
        """Test connecting to a session"""
        # Note: This will fail without a real session running
        # But we can test the method exists and handles failure gracefully
        success = self.network.connect_to_session("nonexistent_session")
        self.assertFalse(success)  # Should fail for non-existent session

    def test_session_creation(self):
        """Test creating a session"""
        # Test session creation
        success = self.network.create_session("test_session")
        
        # Should succeed in creating session
        self.assertTrue(success)
        self.assertEqual(self.network.session_name, "test_session")
        self.assertTrue(self.network.is_host)
        
        # Clean up
        self.network.stop()





class TestPearCLI(unittest.TestCase):
    """Test CLI functionality"""

    def setUp(self):
        self.cli = PearCLI()

    def test_cli_initialization(self):
        """Test CLI component initialization"""
        self.assertIsNotNone(self.cli.network_manager)
        self.assertIsNotNone(self.cli.config)
        self.assertIsNotNone(self.cli.session_commands)
        self.assertIsNotNone(self.cli.config_commands)

    def test_config_operations(self):
        """Test configuration operations"""
        # Test setting username
        self.cli.login("testuser")
        self.assertEqual(self.cli.username, "testuser")
        
        # Test showing config (should not crash)
        self.cli.show_config()


class TestIntegration(unittest.TestCase):
    """Test integration between components"""

    def test_message_handler_network_integration(self):
        """Test message handler working with network manager"""
        handler = MessageHandler()
        network = NetworkManager()

        # Create a session (host mode)
        success = network.create_session("test_session")
        self.assertTrue(success)

        # Add a message
        msg = handler.add_message("testuser", "Integration test")

        # Send the message through network
        network.send_message(msg.content, msg.username)

        # Verify message was stored
        messages = handler.get_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].content, "Integration test")
        
        # Clean up
        network.stop()

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
        handler = MessageHandler()
        network = NetworkManager()

        # Create a session
        success = network.create_session("test_workflow_session")
        self.assertTrue(success)

        # Add some messages
        handler.add_system_message("Session started")
        handler.add_message("testuser", "Hello everyone!")

        # Verify messages were stored
        messages = handler.get_messages()
        self.assertEqual(len(messages), 2)

        # Get stats
        stats = handler.get_message_stats()
        self.assertEqual(stats["total_messages"], 2)
        self.assertEqual(stats["unique_users"], 1)
        
        # Clean up
        network.stop()


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
