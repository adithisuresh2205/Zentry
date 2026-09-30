"""
SentinelGate — Database Seeder Script
======================================
Populates default accounts and initial configuration into PostgreSQL database.
"""
import asyncio
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from sqlalchemy import select
from backend.database.session import init_db, close_db, get_session_factory
from backend.database.models import User
from backend.auth.service import hash_password

DEFAULT_USERS = [
    {"username": "admin", "password": "admin123", "role": "ADMIN"},
    {"username": "analyst", "password": "analyst123", "role": "ANALYST"},
    {"username": "user", "password": "user123", "role": "USER"},
]

async def seed():
    print("Initializing DB session...")
    await init_db()
    session_factory = get_session_factory()

    async with session_factory() as session:
        for u in DEFAULT_USERS:
            stmt = select(User).where(User.username == u["username"])
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()
            if not existing:
                user = User(
                    username=u["username"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                    is_active=True,
                )
                session.add(user)
                print(f"Created user: {u['username']} ({u['role']})")
            else:
                print(f"User '{u['username']}' already exists.")
        await session.commit()
    
    await close_db()
    print("Seeding complete.")

if __name__ == "__main__":
    asyncio.run(seed())
