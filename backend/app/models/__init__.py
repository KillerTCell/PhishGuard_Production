"""ORM model registry — imports all 11 models so Alembic autogenerate
sees them when it inspects ``Base.metadata``.

Import order follows FK dependency (parents before children) to avoid
forward-reference issues during metadata reflection.
"""
from app.models.organisation import Organisation
from app.models.user import User
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.analysis_result import AnalysisResult
from app.models.feedback import Feedback
from app.models.digest_log import DigestLog
from app.models.audit_log import AuditLog
from app.models.invite_token import InviteToken
from app.models.password_reset_token import PasswordResetToken
from app.models.export_job import ExportJob

__all__ = [
    "Organisation",
    "User",
    "Email",
    "EmailFeature",
    "AnalysisResult",
    "Feedback",
    "DigestLog",
    "AuditLog",
    "InviteToken",
    "PasswordResetToken",
    "ExportJob",
]
