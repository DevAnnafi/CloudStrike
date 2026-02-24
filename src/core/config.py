"""Multi-account configuration parser for CloudSecure v2."""

import yaml
from pathlib import Path


class MultiAccountConfig:
    """
    Parses and validates multi-account environment configurations.
    
    Loads YAML configuration files defining AWS accounts, Azure subscriptions,
    and GCP projects organized by environment (production, staging, etc.).
    """
    
    def __init__(self, config_path):
        """
        Initialize config parser.
        
        Args:
            config_path (str): Path to YAML configuration file.
        """
        self.config_path = Path(config_path)
        self.config = {}
    
    def load(self):
        """
        Load and parse the configuration file.
        
        Returns:
            dict: Parsed configuration organized by environment.
            
        Raises:
            FileNotFoundError: If config file doesn't exist.
            ValueError: If config file is invalid YAML.
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}")
    
        self.validate()
        
        return self.config
    
    def get_environment(self, env_name):
        """
        Get configuration for a specific environment.
        
        Args:
            env_name (str): Environment name (e.g., 'production', 'staging').
            
        Returns:
            dict: Environment configuration with aws/azure/gcp accounts.
            
        Raises:
            ValueError: If environment doesn't exist in config.
        """
       
        if env_name not in self.config:
            available = list(self.config.keys())
            raise ValueError(f"Environment '{env_name}' not found. Available: {available}")
        
        return self.config[env_name]
    
    def validate(self):
        """
        Validate configuration structure and required fields.
        
        Raises:
            ValueError: If configuration is invalid.
        """
        if not isinstance(self.config, dict):
            raise ValueError("Config must be a dictionary of environments")
    
        for env_name, env_config in self.config.items():
            if not isinstance(env_config, dict):
                raise ValueError(f"Environment '{env_name}' must be a dictionary")
            
            if 'aws' in env_config:
                if not isinstance(env_config['aws'], list):
                    raise ValueError(f"Aws config in '{env_name}' must be a list")
                
                for account in env_config['aws']:
                    if 'profile' not in account:
                        raise ValueError(f"AWS account in '{env_name}' missing 'profile' field")
                
            if 'azure' in env_config:
                if not isinstance(env_config['azure'], list):
                    raise ValueError(f"Azure config in '{env_name}' must be a list")
                
                for account in env_config['azure']:
                    if 'subscription_id' not in account:
                        raise ValueError(f"Azure account in '{env_name}' missing 'subscription_id' field")
                      
            if 'gcp' in env_config:
                if not isinstance(env_config['gcp'], list):
                    raise ValueError(f"GCP config in '{env_name}' must be a list")
                
                for account in env_config['gcp']:
                    if 'project_id' not in account:
                        raise ValueError(f"GCP account in '{env_name}' missing 'project_id' field")
                
              