from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent


class StorageConfig(BaseSettings):
    sessions_dir: Path = Field(default=PACKAGE_DIR / "sessions", description="Directory to store graph session files.")

class AnalysisConfig(BaseSettings):
    num_paths_to_find: int = Field(default=5, gt=0, description="The default number of attack paths to generate.")
    max_attack_cost: int = Field(default=25, gt=0, description="The maximum total cost for an attack path search, to prevent infinite loops.")


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="__")
    storage: StorageConfig = StorageConfig()
    analysis: AnalysisConfig = AnalysisConfig()

APP_CONFIG = AppConfig()