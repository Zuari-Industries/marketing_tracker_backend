import os
from sqlalchemy import create_engine, MetaData, Table, select

# -------------------------
# Step 1: Connect to SQLite
# -------------------------
sqlite_path = "instance/marketing_hub.db"
sqlite_engine = create_engine(f"sqlite:///{sqlite_path}")
sqlite_conn = sqlite_engine.connect()
sqlite_metadata = MetaData()
sqlite_metadata.reflect(bind=sqlite_engine)

# Verify tables exist
sqlite_tables = list(sqlite_metadata.tables.keys())
if not sqlite_tables:
    raise ValueError(f"No tables found in SQLite DB at {sqlite_path}")
print("SQLite tables found:", sqlite_tables)

# -------------------------
# Step 2: Connect to Neon
# -------------------------
NEON_URL = os.getenv("DATABASE_URL")
if not NEON_URL:
    raise ValueError("Please set the DATABASE_URL env variable for Neon!")

neon_engine = create_engine(NEON_URL)
neon_metadata = MetaData()
neon_metadata.reflect(bind=neon_engine)

# -------------------------
# Step 3: Create tables in Neon if missing
# -------------------------
for table_name in sqlite_tables:
    if table_name not in neon_metadata.tables:
        table = Table(table_name, sqlite_metadata, autoload_with=sqlite_engine)
        table.metadata.create_all(neon_engine)
        print(f"Created table {table_name} in Neon")

# -------------------------
# Step 4: Define parent-first migration order
# -------------------------
# Adjust this order based on foreign key dependencies in your DB
tables_order = [
    "user",             # parent of request, comment, notification, etc.
    "activity_log",     # optional, may reference user
    "request",          # depends on user
    "comment",          # depends on request and user
    "form_field",       # depends on request
    "notification",     # depends on user
    "subtask_template", # independent
    "subtask"           # depends on request
]

# -------------------------
# Step 5: Fetch valid parent IDs for filtering
# -------------------------
def get_column_values(table_name, column_name):
    table = sqlite_metadata.tables[table_name]
    rows = sqlite_conn.execute(select(table)).fetchall()
    return {row._mapping[column_name] for row in rows}

user_ids = get_column_values("user", "id")
request_ids = get_column_values("request", "id")

# -------------------------
# Step 6: Migrate tables safely
# -------------------------
for table_name in tables_order:
    table = sqlite_metadata.tables[table_name]
    sqlite_rows = sqlite_conn.execute(select(table)).fetchall()

    if not sqlite_rows:
        print(f"No rows to migrate for table {table_name}")
        continue

    rows_to_insert = []
    for row in sqlite_rows:
        row_dict = dict(row._mapping)

        # Filter FK references to existing parent IDs
        if table_name == "request":
            if row_dict.get("created_by_id") not in user_ids:
                continue
        elif table_name == "comment":
            if row_dict.get("request_id") not in request_ids or row_dict.get("created_by_id") not in user_ids:
                continue
        elif table_name == "notification":
            if row_dict.get("user_id") not in user_ids:
                continue
        elif table_name == "subtask":
            if row_dict.get("request_id") not in request_ids:
                continue

        rows_to_insert.append(row_dict)

    if rows_to_insert:
        with neon_engine.begin() as conn:
            conn.execute(table.insert(), rows_to_insert)
        print(f"Inserted {len(rows_to_insert)} rows into {table_name}")
    else:
        print(f"No valid rows to migrate for table {table_name}")

# -------------------------
# Step 7: Close SQLite connection
# -------------------------
sqlite_conn.close()
print("Migration complete!")
