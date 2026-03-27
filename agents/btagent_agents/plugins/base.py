"""DefensivePlugin abstract base class for BTagent plugin system."""

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field


class DefensivePluginMetadata(BaseModel):
    """Metadata describing a defensive security plugin."""

    name: str
    description: str
    version: str
    author: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    supported_data_sources: list[str] = Field(default_factory=list)


class DefensivePlugin(ABC):
    """Abstract base class for all BTagent defensive plugins.

    Each plugin encapsulates a security capability (triage, query generation,
    enrichment, etc.) and exposes LangChain tools, a system prompt, and metadata
    for the orchestrator to compose into agent subgraphs.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the plugin (e.g. 'triage', 'query')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the plugin's purpose."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string (e.g. '1.0.0')."""
        ...

    @abstractmethod
    def get_tools(self) -> list:
        """Return a list of LangChain BaseTool instances provided by this plugin."""
        ...

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for the agent that uses this plugin."""
        ...

    @abstractmethod
    def get_metadata(self) -> DefensivePluginMetadata:
        """Return structured metadata about the plugin."""
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} v{self.version}>"
