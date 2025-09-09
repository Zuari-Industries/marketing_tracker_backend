# create_tables_neon.py
import os
from app import db  # Make sure this imports your SQLAlchemy db and all models
from sqlalchemy import create_engine

NEON_URL = os.getenv("DATABASE_URL")
if not NEON_URL:
    raise ValueError("Please set the DATABASE_URL environment variable!")

neon_engine = create_engine(NEON_URL)

# Create all tables defined in ORM in Neon
db.metadata.create_all(bind=neon_engine)
print("All tables created in Neon!")
