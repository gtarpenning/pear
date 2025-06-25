# 🍐 Pear - P2P Terminal Chat MVP

A peer-to-peer command line messaging tool for local network communication with a beautiful terminal interface powered by Rich.

## Features

- 🌐 **P2P Networking**: Direct peer-to-peer connections (currently mocked)
- 💬 **Real-time Chat**: Beautiful terminal-based chat interface
- 🔍 **Network Discovery**: Find active chat sessions on your network
- 👥 **Multi-user Support**: Multiple users in the same chat session
- 🎨 **Rich UI**: Beautiful terminal interface with panels, colors, and layouts
- ⚡ **Commands**: Built-in chat commands (/help, /quit, /stats, etc.)
- 🤖 **AI Assistant**: Chat with LLM-powered AI agents using litellm

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Make the CLI executable:**
   ```bash
   chmod +x pear_cli.py
   ```

## Usage

### Basic Commands

```bash
# Show help
python pear_cli.py --help

# Start a new chat session
python pear_cli.py start [session_name]

# Join an existing session
python pear_cli.py join [session_name]

# List available sessions
python pear_cli.py list
```

### Interactive Chat Commands

Once in a chat session, you can use these commands:

- `/help` - Show available commands
- `/quit` or `/exit` - Leave the chat
- `/clear` - Clear message history
- `/stats` - Show chat statistics
- `/users` - Show connected users
- `/llm activate [name]` - Invite AI assistant to chat (with optional custom name)
- `/llm deactivate` - Remove AI assistant from chat
- `/llm model <model_name>` - Change AI model (e.g., gpt-4, claude-3, etc.)

### Testing

Run the test suite to verify all components work:

```bash
python test_pear.py
```

## MVP Architecture

The MVP consists of several modular components:

### 1. CLI Interface (`pear_cli.py`)
- Main entry point with argument parsing
- Command routing (start, join, list)
- Integration between all components

### 2. Network Layer (`network_layer.py`)
- P2P networking functionality (currently mocked)
- Session discovery and connection management
- Message broadcasting to peers

### 3. Message System (`message_system.py`)
- Message handling and storage
- Callback system for real-time updates
- Message formatting and statistics

### 4. Terminal UI (`terminal_ui.py`)
- Rich-powered beautiful terminal interface
- Live updating chat display
- User input handling and command processing

### 5. LLM Agent (`llm_agent.py`)
- AI assistant integration using litellm
- Context-aware responses based on chat history
- Random woman names for personalized experience
- Mention-based activation (responds when name is mentioned)

## Current State

This is an **MVP with mocked networking**. The P2P networking components are currently simulated for testing and development purposes.

### What Works:
✅ CLI argument parsing and command routing  
✅ Beautiful terminal interface with Rich  
✅ Message system with callbacks  
✅ Mock network discovery and sessions  
✅ Interactive chat interface  
✅ Chat commands and user management  
✅ AI assistant integration with litellm  
✅ Context-aware LLM responses  

### Next Steps:
🔄 Implement real UDP discovery protocol  
🔄 Implement real TCP messaging between peers  
🔄 Add proper connection management  
🔄 Add user authentication  
🔄 Add message encryption  

## Example Usage

1. **Start a session:**
   ```bash
   python pear_cli.py start my_chat
   ```

2. **In another terminal, join the session:**
   ```bash
   python pear_cli.py join my_chat
   ```

3. **List available sessions:**
   ```bash
   python pear_cli.py list
   ```

## AI Assistant Setup

To use the AI assistant feature:

1. **Install litellm:**
   ```bash
   pip install litellm
   ```

2. **Set up your API key** (example for OpenAI):
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

3. **Available models:**
   - OpenAI: `gpt-3.5-turbo`, `gpt-4`, `gpt-4o`
   - Anthropic: `claude-3-sonnet`, `claude-3-haiku`
   - And many more via litellm

4. **Usage:**
   ```bash
   # Start a chat session
   python pear_cli.py start
   
   # Activate AI assistant
   /llm activate
   
   # Chat with the AI by mentioning her name
   "Hey Sarah, tell me about pelicans please"
   ```

## Dependencies

- **rich**: Beautiful terminal interface components
- **litellm**: LLM integration for AI assistant
- **Python 3.7+**: Required for modern Python features

## Development

The codebase is structured for easy extension:

- All networking is abstracted in `NetworkManager`
- Message handling is separate from UI
- Rich components make the UI easily customizable
- Mock implementations allow testing without network setup

To extend functionality, focus on replacing the mock methods in `NetworkManager` with real UDP/TCP implementations. 