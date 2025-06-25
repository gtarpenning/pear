#!/usr/bin/env python3
"""
Pear Configuration Management
Handles user preferences and config storage
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any


class PearConfig:
    def __init__(self):
        self.config_dir = Path.home() / ".pear"
        self.config_file = self.config_dir / "config.json"
        self._ensure_config_dir()
        self._config = self._load_config()
    
    def _ensure_config_dir(self):
        """Ensure config directory exists"""
        self.config_dir.mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save config: {e}")
    
    def get_username(self) -> Optional[str]:
        """Get stored username"""
        return self._config.get('username')
    
    def set_username(self, username: str):
        """Set and save username"""
        self._config['username'] = username
        self._save_config()
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting"""
        return self._config.get(key, default)
    
    def set_setting(self, key: str, value: Any):
        """Set and save a configuration setting"""
        self._config[key] = value
        self._save_config()
    
    def clear_config(self):
        """Clear all configuration"""
        self._config = {}
        self._save_config()
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all configuration settings"""
        return self._config.copy()