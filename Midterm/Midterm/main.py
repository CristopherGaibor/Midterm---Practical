import os
from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select
from fastapi import FastAPI, HTTPException
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()
PEPPER = os.getenv("SECRET_PEPPER", "ClaveSeguraProvicional123")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password + PEPPER)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password + PEPPER, hashed_password)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str

sqlite_url = "sqlite:///database.db"
engine = create_engine(sqlite_url)

app = FastAPI()

@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

@app.post("/register")
def register(user: User):
    with Session(engine) as session:
        statement = select(User).where(User.username == user.username)
        if session.exec(statement).first():
            raise HTTPException(status_code=400, detail="El usuario ya existe")
        
        user.hashed_password = hash_password(user.hashed_password)
        session.add(user)
        session.commit()
        return {"status": "success", "username": user.username}

@app.post("/login")
def login(user: User):
    with Session(engine) as session:
        statement = select(User).where(User.username == user.username)
        db_user = session.exec(statement).first()
        if not db_user or not verify_password(user.hashed_password, db_user.hashed_password):
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        return {"message": "Bienvenido!"}