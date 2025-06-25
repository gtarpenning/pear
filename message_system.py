"""
Message System - Handles chat messages and routing
"""

import time
from typing import List, Callable, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ChatMessage:
    """Represents a chat message"""

    username: str
    content: str
    timestamp: float
    message_id: str
    message_type: str = "text"  # text, system, notification

    def formatted_time(self) -> str:
        """Get formatted timestamp for display"""
        dt = datetime.fromtimestamp(self.timestamp)
        return dt.strftime("%H:%M:%S")

    def formatted_datetime(self) -> str:
        """Get formatted datetime for display"""
        dt = datetime.fromtimestamp(self.timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")


class MessageHandler:
    """Handles message processing, storage, and callbacks"""

    def __init__(self):
        self.messages: List[ChatMessage] = []
        self.message_callbacks: List[Callable[[ChatMessage], None]] = []
        self.max_messages = 1000  # Keep last 1000 messages

    def add_message_callback(self, callback: Callable[[ChatMessage], None]):
        """Add a callback to be called when new messages arrive"""
        self.message_callbacks.append(callback)

    def remove_message_callback(self, callback: Callable[[ChatMessage], None]):
        """Remove a message callback"""
        if callback in self.message_callbacks:
            self.message_callbacks.remove(callback)

    def add_message(
        self, username: str, content: str, message_type: str = "text"
    ) -> ChatMessage:
        """Add a new message to the chat"""
        import uuid

        message = ChatMessage(
            username=username,
            content=content,
            timestamp=time.time(),
            message_id=str(uuid.uuid4()),
            message_type=message_type,
        )

        self.messages.append(message)

        # Keep only the last max_messages
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages :]

        # Notify all callbacks
        for callback in self.message_callbacks:
            try:
                callback(message)
            except Exception as e:
                print(f"Error in message callback: {e}")

        return message

    def add_system_message(self, content: str) -> ChatMessage:
        """Add a system message (like user joined/left notifications)"""
        return self.add_message("SYSTEM", content, "system")

    def get_messages(self, limit: Optional[int] = None) -> List[ChatMessage]:
        """Get chat messages, optionally limited to recent messages"""
        if limit is None:
            return self.messages.copy()
        return self.messages[-limit:] if limit > 0 else []

    def get_messages_since(self, timestamp: float) -> List[ChatMessage]:
        """Get messages since a specific timestamp"""
        return [msg for msg in self.messages if msg.timestamp > timestamp]

    def clear_messages(self):
        """Clear all messages"""
        self.messages.clear()

    def format_message_for_display(self, message: ChatMessage) -> str:
        """Format a message for terminal display"""
        if message.message_type == "system":
            return f"[{message.formatted_time()}] * {message.content}"
        else:
            return f"[{message.formatted_time()}] {message.username}: {message.content}"

    def search_messages(self, query: str) -> List[ChatMessage]:
        """Search messages by content"""
        query_lower = query.lower()
        return [
            msg
            for msg in self.messages
            if query_lower in msg.content.lower() or query_lower in msg.username.lower()
        ]

    def get_user_messages(self, username: str) -> List[ChatMessage]:
        """Get all messages from a specific user"""
        return [msg for msg in self.messages if msg.username == username]

    def get_message_stats(self) -> dict:
        """Get statistics about messages"""
        if not self.messages:
            return {
                "total_messages": 0,
                "unique_users": 0,
                "first_message_time": None,
                "last_message_time": None,
            }

        users = set(
            msg.username for msg in self.messages if msg.message_type != "system"
        )

        return {
            "total_messages": len(self.messages),
            "unique_users": len(users),
            "first_message_time": self.messages[0].timestamp,
            "last_message_time": self.messages[-1].timestamp,
            "user_message_counts": {
                user: len([msg for msg in self.messages if msg.username == user])
                for user in users
            },
        }


class MockMessageRouter:
    """Mock message router for testing message flow"""

    def __init__(self, message_handler: MessageHandler):
        self.message_handler = message_handler
        self.running = False
        self.mock_users = ["alice", "bob", "charlie"]
        self.mock_messages = [
            "Hey everyone!",
            "How's the project going?",
            "Just pushed the latest changes",
            "Anyone want to grab coffee?",
            "The deployment looks good",
            "Thanks for the help earlier",
            "See you tomorrow!",
            "Working on the docs now",
            "Found a small bug, fixing it",
            "All tests are passing ✅",
        ]

    def start_mock_simulation(self):
        """Start simulating incoming messages for testing"""
        import threading
        import random

        self.running = True

        def simulate_messages():
            import time

            while self.running:
                # Wait 5-15 seconds between messages
                time.sleep(random.randint(5, 15))

                if not self.running:
                    break

                # Send a random message from a random user
                user = random.choice(self.mock_users)
                message = random.choice(self.mock_messages)

                self.message_handler.add_message(user, message)

        thread = threading.Thread(target=simulate_messages)
        thread.daemon = True
        thread.start()

    def stop_mock_simulation(self):
        """Stop the mock message simulation"""
        self.running = False
