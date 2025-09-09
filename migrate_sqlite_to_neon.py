import os
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import select

# -------------------------
# Step 1: Connect to SQLite
# -------------------------
sqlite_path = "marketing_hub.db"
sqlite_engine = create_engine(f"sqlite:///{sqlite_path}")
sqlite_conn = sqlite_engine.connect()
sqlite_metadata = MetaData()
sqlite_metadata.reflect(bind=sqlite_engine)

# -------------------------
# Step 2: Connect to Neon
# -------------------------
NEON_URL = os.getenv("DATABASE_URL")
if not NEON_URL:
    raise ValueError("Please set the DATABASE_URL env variable for Neon!")

neon_engine = create_engine(NEON_URL)
neon_conn = neon_engine.connect()
neon_metadata = MetaData()
neon_metadata.reflect(bind=neon_engine)

# -------------------------
# Step 3: Create tables in Neon if they don't exist
# -------------------------
for table_name in sqlite_metadata.tables:
    if table_name not in neon_metadata.tables:
        # get table from SQLite
        table = Table(table_name, sqlite_metadata, autoload_with=sqlite_engine)
        table.metadata.create_all(neon_engine)
        print(f"Created table {table_name} in Neon")

# -------------------------
# Step 4: Migrate data
# -------------------------
for table_name, table in sqlite_metadata.tables.items():
    print(f"Migrating table: {table_name}")
    sqlite_rows = sqlite_conn.execute(select(table)).fetchall()
    if sqlite_rows:
        # insert into Neon
        neon_conn.execute(table.insert(), [dict(row) for row in sqlite_rows])
        print(f"Inserted {len(sqlite_rows)} rows into {table_name}")

# -------------------------
# Step 5: Close connections
# -------------------------
sqlite_conn.close()
neon_conn.close()
print("Migration complete!")
