"""Model registry — import all models so Base.metadata is complete."""
from app.db.base import Base  # noqa: F401
from app.models.alert import *  # noqa: F401,F403
from app.models.audit import *  # noqa: F401,F403
from app.models.event import *  # noqa: F401,F403
from app.models.incident import *  # noqa: F401,F403
from app.models.scenario import *  # noqa: F401,F403
from app.models.simulation import *  # noqa: F401,F403
from app.models.user import *  # noqa: F401,F403
