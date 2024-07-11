from fastapi import Form
from sqlmodel import Field, SQLModel
from pydantic import BaseModel

from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated


class Todo(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str = Field(index=True, min_length=3, max_length=54)
    is_completed: bool = Field(default=False)
    user_id:int = Field(foreign_key="user.id")

class User(SQLModel,table=True):
    id: int | None = Field(default=None, primary_key=True)
    username:str
    email:str
    password:str
    

class Register_User(BaseModel):
    username: Annotated[str, Form()]
    email: Annotated[str, Form()]
    password: Annotated[str, Form()]
    
    
    
class Token(BaseModel):
    access_token: str
    token_Type: str
    refresh_token:str
    
class TokenData(BaseModel):
    username:str    
    
class TokenRefresh(BaseModel):
    email:str    
        
    
    
class Todo_Create(BaseModel):
       content: str = Field(index=True, min_length=3, max_length=54)
       

class Todo_Edit(BaseModel):
    content: str = Field(index=True, min_length=3, max_length=54)
    is_completed: bool = Field(default=False)

           