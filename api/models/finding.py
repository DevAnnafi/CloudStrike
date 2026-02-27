from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from api.core.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    cloud_provider = Column(String, nullable=False)
    account_id_value = Column(String, nullable=False)
    account_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")
