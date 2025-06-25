#!/usr/bin/env python3
"""
LLM Demo - Showcase the new AI assistant feature
"""

import os
import time
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from message_system import MessageHandler
from llm_agent import LLMAgent
from rich.console import Console
from rich.panel import Panel

def main():
    console = Console()
    
    # Show demo banner
    console.print(Panel.fit(
        "[bold cyan]🍐 Pear Chat - LLM Agent Demo[/bold cyan]\n"
        "[dim]This demo shows how to use the new AI assistant feature[/dim]",
        border_style="cyan"
    ))
    
    # Initialize components
    message_handler = MessageHandler()
    llm_agent = LLMAgent(message_handler)
    
    console.print("\n[bold green]Setting up demo environment...[/bold green]")
    
    # Add some sample messages to create context
    message_handler.add_message("alice", "Hey everyone! How's the project going?")
    time.sleep(0.5)
    message_handler.add_message("bob", "Pretty good! Just finished the network layer")
    time.sleep(0.5)
    message_handler.add_system_message("Demo user joined the chat")
    
    # Show initial state
    console.print("\n[bold yellow]💬 Current chat context:[/bold yellow]")
    for msg in message_handler.get_messages():
        timestamp = msg.formatted_time()
        if msg.message_type == "system":
            console.print(f"[dim][{timestamp}] * {msg.content}[/dim]")
        else:
            console.print(f"[dim][{timestamp}] {msg.username}: {msg.content}[/dim]")
    
    console.print("\n[bold green]🤖 Activating AI assistant...[/bold green]")
    
    try:
        # Activate the LLM agent
        agent_name = llm_agent.activate()
        console.print(f"[green]✅ AI assistant '{agent_name}' is now active![/green]")
        
        console.print(f"\n[bold cyan]Demo Usage Examples:[/bold cyan]")
        console.print(f"1. Mention {agent_name} by name to get her attention")
        console.print(f"2. Example: 'Hey {agent_name}, tell me about pelicans please'")
        console.print(f"3. Example: '{agent_name}, what do you think about our project?'")
        
        # Simulate user interactions
        console.print(f"\n[bold yellow]📝 Simulating user messages...[/bold yellow]")
        
        # First interaction
        user_message = f"Hey {agent_name}, tell me about pelicans please"
        console.print(f"[blue]User: {user_message}[/blue]")
        message_handler.add_message("demo_user", user_message)
        
        # Wait for response
        console.print("[dim]Waiting for AI response...[/dim]")
        time.sleep(5)  # Give time for the AI to respond
        
        # Show recent messages
        recent_messages = message_handler.get_messages()[-5:]  # Last 5 messages
        console.print(f"\n[bold yellow]💬 Recent conversation:[/bold yellow]")
        for msg in recent_messages:
            timestamp = msg.formatted_time()
            if msg.message_type == "system":
                console.print(f"[dim][{timestamp}] * {msg.content}[/dim]")
            elif msg.username == agent_name:
                console.print(f"[magenta][{timestamp}] {msg.username}: {msg.content}[/magenta]")
            else:
                console.print(f"[blue][{timestamp}] {msg.username}: {msg.content}[/blue]")
        
        # Second interaction
        console.print(f"\n[bold yellow]📝 Another interaction...[/bold yellow]")
        user_message2 = f"{agent_name}, what programming language do you recommend for beginners?"
        console.print(f"[blue]User: {user_message2}[/blue]")
        message_handler.add_message("demo_user", user_message2)
        
        console.print("[dim]Waiting for AI response...[/dim]")
        time.sleep(5)
        
        # Show final messages
        final_messages = message_handler.get_messages()[-3:]
        console.print(f"\n[bold yellow]💬 Final conversation:[/bold yellow]")
        for msg in final_messages:
            timestamp = msg.formatted_time()
            if msg.message_type == "system":
                console.print(f"[dim][{timestamp}] * {msg.content}[/dim]")
            elif msg.username == agent_name:
                console.print(f"[magenta][{timestamp}] {msg.username}: {msg.content}[/magenta]")
            else:
                console.print(f"[blue][{timestamp}] {msg.username}: {msg.content}[/blue]")
        
        console.print(f"\n[bold green]✅ Demo completed successfully![/bold green]")
        console.print(f"\n[bold cyan]To use in Pear Chat:[/bold cyan]")
        console.print(f"1. Start a chat session: [code]python pear_cli.py start[/code]")
        console.print(f"2. Use command: [code]/llm activate[/code]")
        console.print(f"3. Chat with the AI by mentioning her name!")
        
        # Deactivate
        llm_agent.deactivate()
        console.print(f"\n[dim]AI assistant deactivated.[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Demo failed: {str(e)}[/red]")
        console.print("[yellow]Note: You may need to set up your API keys for the LLM to work.[/yellow]")
        console.print("[yellow]Example: export OPENAI_API_KEY='your-key-here'[/yellow]")

if __name__ == "__main__":
    main() 