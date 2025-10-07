from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class StorageConfig(BaseSettings):
    sessions_dir: Path = Field(default=Path("sessions"), description="Directory to store graph session files.")

class AnalysisConfig(BaseSettings):
    max_path_length: int = Field(default=10, gt=0, description="Maximum number of steps to explore in a single attack path.")
    default_strategy: str = Field(default="GreedyDFSStrategy", description="The default pathfinding strategy to use.")

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="__")
    storage: StorageConfig = StorageConfig()
    analysis: AnalysisConfig = AnalysisConfig()

APP_CONFIG = AppConfig()