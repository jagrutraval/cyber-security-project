from datetime import datetime

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)


DATABASE_URL = "sqlite:///scan_history.db"


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


Base = declarative_base()



class ScanHistory(Base):

    __tablename__ = "scans"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    filename = Column(
        String,
        nullable=False
    )


    username = Column(
        String
    )


    file_hash = Column(
        String,
        nullable=False
    )


    antivirus = Column(
        String
    )


    yara = Column(
        String
    )


    risk_score = Column(
        Integer
    )


    risk_level = Column(
        String
    )


    scan_date = Column(
        DateTime,
        default=datetime.utcnow
    )






class User(Base):

    __tablename__ = "users"


    id = Column(
        Integer,
        primary_key=True
    )


    username = Column(
        String,
        unique=True,
        nullable=False
    )


    password = Column(
        String,
        nullable=False
    )






class QuarantineFile(Base):

    __tablename__ = "quarantine_files"


    id = Column(
        Integer,
        primary_key=True
    )


    filename = Column(
        String,
        nullable=False
    )


    username = Column(
        String
    )


    original_path = Column(
        String,
        nullable=False
    )


    quarantine_path = Column(
        String,
        nullable=False
    )


    reason = Column(
        String
    )


    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


    file_size = Column(
        Integer,
        default=0
    )


    risk_level = Column(
        String,
        default="HIGH"
    )



Base.metadata.create_all(
    bind=engine
)