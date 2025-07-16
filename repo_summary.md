# Pear Chat Repository Summary

This is a Python package called `pear-chat` - a P2P terminal chat application for local networks.

## Repository Structure

**Core files:**
- `pear/` - Main package directory with networking, messaging, and CLI components
- `pyproject.toml` - Package configuration and dependencies
- `README.md` - Documentation showing it's a terminal chat app

**Key components:**
- `pear_cli.py` - CLI interface 
- `enhanced_network_layer.py` - Enhanced networking functionality
- `message_system.py` - Message handling
- `llm_agent.py` - LLM integration
- `network_analyzer.py` - Network diagnostics
- `simple_terminal_ui.py` - Terminal UI

## Usage

Install with `pip install pear-chat`, then use commands like:
- `pear start mysession` - Create a chat session
- `pear join mysession` - Join an existing session
- `pear list` - List available sessions
- `pear login myusername` - Set username for future sessions

## Package Details

- **Version:** 0.1.3
- **License:** MIT
- **Python:** >=3.8
- **Dependencies:** rich>=12.0.0, litellm>=1.0.0
- **Author:** Griffin Tarpenning