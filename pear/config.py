#!/usr/bin/env python3
"""
Pear Configuration Management
Handles user preferences and configuration storage
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any


class PearConfig:
    def __init__(self):
        self.config_dir = Path.home() / ".pear"
        self.config_file = self.config_dir / "config.json"
        self._config = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._config = {}
        else:
            self._config = {}

    def _save_config(self):
        """Save configuration to file"""
        self.config_dir.mkdir(exist_ok=True)
        try:
            with open(self.config_file, "w") as f:
                json.dump(self._config, f, indent=2)
        except IOError as e:
            raise RuntimeError(f"Failed to save config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        """Set a configuration value"""
        self._config[key] = value
        self._save_config()

    def get_username(self) -> Optional[str]:
        """Get the stored username"""
        return self.get("username")

    def set_username(self, username: str):
        """Set the username"""
        self.set("username", username)

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values"""
        return self._config.copy()

    def clear(self):
        """Clear all configuration"""
        self._config = {}
        self._save_config()
