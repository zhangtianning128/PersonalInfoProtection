# 文件：create_db.py

from sqlalchemy import create_engine, Table, MetaData, Column, String

import time

start_time = time.time()

engine = create_engine('sqlite:///mydata.db')

metadata = MetaData()

users = Table('users', metadata,
    Column('id', String, primary_key=True),
    Column('encrypted_data', String),
)

metadata.create_all(engine)

end_time = time.time()

print(f"Create Database time: {end_time - start_time} seconds")
