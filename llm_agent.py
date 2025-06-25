"""
LLM Agent - Handles LLM chatbot integration using litellm
"""

import random
import threading
import time
from typing import Optional, List
from datetime import datetime

try:
    import litellm
except ImportError:
    litellm = None

from message_system import MessageHandler, ChatMessage


class LLMAgent:
    """LLM-powered chat agent that can participate in conversations"""

    WOMAN_NAMES = [
        "Wendy",
        "Sarah",
        "Emma",
        "Olivia",
        "Sophia",
        "Isabella",
        "Ava",
        "Mia",
        "Charlotte",
        "Amelia",
        "Harper",
        "Evelyn",
        "Abigail",
        "Emily",
        "Ella",
        "Elizabeth",
        "Camila",
        "Luna",
        "Sofia",
        "Avery",
        "Grace",
        "Scarlett",
        "Victoria",
        "Aria",
        "Chloe",
        "Madison",
        "Eleanor",
        "Layla",
        "Penelope",
    ]

    def __init__(self, message_handler: MessageHandler, network_manager=None):
        self.message_handler = message_handler
        self.network_manager = network_manager
        self.name = None
        self.active = False
        self.context_window = 20  # Number of recent messages to include as context
        self.model = "gpt-4o"  # Default model

        # Add callback to monitor messages
        self.message_handler.add_message_callback(self._on_message_received)

    def activate(self, custom_name: Optional[str] = None) -> str:
        """Activate the LLM agent with a random or custom name"""
        self.name = custom_name or random.choice(self.WOMAN_NAMES)
        self.active = True

        # No welcome message - AI should only respond when spoken to

        return self.name

    def deactivate(self):
        """Deactivate the LLM agent"""
        if self.active and self.name:
            # Silent deactivation - no message
            pass

        self.active = False
        self.name = None

    def _on_message_received(self, message: ChatMessage):
        """Called when a new message is received"""
        if not self.active or not self.name or message.username == self.name:
            return

        # Ignore system messages, user events, and AI events - only respond to actual chat messages
        if message.message_type in ["system", "user_event", "ai_event"]:
            return

        # Check if the agent is mentioned by name (case insensitive)
        if self.name.lower() in message.content.lower():
            # Respond in a separate thread to avoid blocking
            threading.Thread(
                target=self._generate_response, args=(message,), daemon=True
            ).start()

    def _generate_response(self, trigger_message: ChatMessage):
        """Generate and send an LLM response"""
        try:
            # Get recent context
            recent_messages = self.message_handler.get_messages()[
                -self.context_window :
            ]

            # Build context for the LLM
            context = self._build_context(recent_messages, trigger_message)

            # Generate response using litellm
            response = litellm.completion(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are {self.name}, a helpful AI assistant participating in a group chat. "
                        f"Be conversational, friendly, and concise. Keep responses brief (1-2 sentences usually). "
                        f"You were mentioned in the most recent message, so respond naturally to the conversation.",
                    },
                    {"role": "user", "content": context},
                ],
                max_tokens=150,
                temperature=0.7,
            )

            ai_response = response.choices[0].message.content.strip()

            # Add a small delay to make it feel more natural
            time.sleep(random.uniform(1, 3))

            # Send the response both locally and through network
            self.message_handler.add_message(self.name, ai_response)

            # Send through network if available
            if self.network_manager:
                self.network_manager.send_message(ai_response, self.name)

        except Exception as e:
            # Send error message
            error_msg = f"Sorry, I'm having trouble connecting to my brain right now 🤯 ({str(e)[:50]}...)"
            self.message_handler.add_message(self.name, error_msg)

            # Send error through network if available
            if self.network_manager:
                self.network_manager.send_message(error_msg, self.name)

    def _build_context(
        self, recent_messages: List[ChatMessage], trigger_message: ChatMessage
    ) -> str:
        """Build context string from recent messages"""
        context_parts = ["Recent conversation:"]

        for msg in recent_messages[-10:]:  # Last 10 messages for context
            if msg.message_type == "system":
                context_parts.append(f"[SYSTEM] {msg.content}")
            else:
                timestamp = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M")
                context_parts.append(f"[{timestamp}] {msg.username}: {msg.content}")

        context_parts.append("")
        context_parts.append(
            f"You are {self.name}. Please respond naturally to the conversation."
        )

        return "\n".join(context_parts)

    def set_model(self, model: str):
        """Set the LLM model to use"""
        self.model = model
        if self.active:
            self.message_handler.add_system_message(
                f"🤖 {self.name} is now using model: {model}"
            )

    def is_active(self) -> bool:
        """Check if the agent is active"""
        return self.active

    def get_name(self) -> Optional[str]:
        """Get the agent's current name"""
        return self.name if self.active else None
