"""
Plugin system for Secomp - extensible architecture for cloud providers and compliance frameworks.
"""

from typing import Dict, Type, Any
from abc import ABC, abstractmethod


class PluginBase(ABC):
    """Base class for Secomp plugins."""

    @abstractmethod
    def get_name(self) -> str:
        """Return plugin name."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Return plugin version."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return plugin description."""
        pass


class CloudScannerPlugin(PluginBase):
    """Plugin interface for cloud resource scanners."""

    @abstractmethod
    def scan_resources(self, config: Dict[str, Any]) -> Any:
        """Scan cloud resources and return findings."""
        pass

    @abstractmethod
    def get_supported_regions(self) -> list:
        """Return list of supported regions."""
        pass


class CompliancePlugin(PluginBase):
    """Plugin interface for compliance frameworks."""

    @abstractmethod
    def check_compliance(self, resource_data: Any) -> Any:
        """Check resource compliance against framework rules."""
        pass

    @abstractmethod
    def get_rules(self) -> list:
        """Return list of compliance rules."""
        pass


class PluginManager:
    """Manages loading and execution of plugins."""

    def __init__(self):
        self.cloud_plugins: Dict[str, Type[CloudScannerPlugin]] = {}
        self.compliance_plugins: Dict[str, Type[CompliancePlugin]] = {}

    def register_cloud_plugin(self, name: str, plugin_class: Type[CloudScannerPlugin]):
        """Register a cloud scanner plugin."""
        self.cloud_plugins[name] = plugin_class

    def register_compliance_plugin(self, name: str, plugin_class: Type[CompliancePlugin]):
        """Register a compliance framework plugin."""
        self.compliance_plugins[name] = plugin_class

    def get_cloud_plugin(self, name: str) -> Optional[Type[CloudScannerPlugin]]:
        """Get a cloud scanner plugin by name."""
        return self.cloud_plugins.get(name)

    def get_compliance_plugin(self, name: str) -> Optional[Type[CompliancePlugin]]:
        """Get a compliance plugin by name."""
        return self.compliance_plugins.get(name)

    def list_cloud_plugins(self) -> list:
        """List all available cloud plugins."""
        return list(self.cloud_plugins.keys())

    def list_compliance_plugins(self) -> list:
        """List all available compliance plugins."""
        return list(self.compliance_plugins.keys())


# Global plugin manager instance
plugin_manager = PluginManager()
