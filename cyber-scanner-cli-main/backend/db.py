"""MongoDB helpers"""
import os
from motor.motor_asyncio import AsyncIOMotorClient

client = AsyncIOMotorClient(os.environ['MONGO_URL'])
db = client[os.environ['DB_NAME']]

users_col = db['users']
scans_col = db['scans']
vulns_col = db['vulnerabilities']
reports_col = db['reports']
terminal_sessions_col = db['terminal_sessions']
