from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import Field, SQLModel, create_engine, Session, select
from fastapi_todoapp1 import setting
from typing import Annotated
from contextlib import asynccontextmanager
from fastapi_todoapp1.router.user import user_router
from fastapi_todoapp1.db import create_tables, get_Session
from fastapi_todoapp1.models import Todo, Token, User, Todo_Create, Todo_Edit
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_todoapp1.auth import EXPIRY_TIME, authenticate_user, create_access_token, create_refresh_token, current_user, validate_refresh_token
from datetime import timedelta
# Creating the model


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield
    ...
app: FastAPI = FastAPI(lifespan=lifespan, title="Todo app", version="1.0.0")


app.include_router(router=user_router)


@app.get("/")
async def root():
    return {"message": "This is the Todo app"}


@app.post("/token", response_model=Token)
async def login(formData: Annotated[OAuth2PasswordRequestForm, Depends()], session: Annotated[Session, Depends(get_Session)]):
    user = authenticate_user(session, formData.username, formData.password)
    if not user:
        HTTPException(status_code=401, detail="Invalid Username or Password")
    expiry_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub": formData.username}, expiry_time)
    
    refrsh_expire_time = timedelta(days=7)
    
    refresh_token = create_refresh_token({"sub":user.email},refrsh_expire_time)

    return Token(access_token=access_token, token_Type="bearer",refresh_token=refresh_token)


@app.post("/refresh/token")
async def refresh_token(old_refresh_token: str, session: Annotated[Session, Depends(get_Session)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, please log in.",
        headers={"www-Authenticate": "Bearer"}
    )

    user = validate_refresh_token(old_refresh_token, session=session)
    if not user:
        raise credentials_exception
    
    
    expiry_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub": user.username}, expiry_time)
    
    refrsh_expire_time = timedelta(days=7)
    
    refresh_token = create_refresh_token({"sub":user.email},refrsh_expire_time)
    
    return Token(access_token=access_token,token_Type="bearer",refresh_token=refresh_token)
   

@app.get("/todos/")
async def getall(current_user: Annotated[User, Depends(current_user)], session: Annotated[Session, Depends(get_Session)]):
    todos = session.exec(select(Todo).where(
        Todo.user_id == current_user.id)).all()
    return todos


@app.post("/todos/")
async def addTodo(
        current_user: Annotated[User, Depends(current_user)],
        todo: Todo_Create,
        session: Annotated[Session, Depends(get_Session)]):
    new_todo = Todo(content=todo.content, user_id=current_user.id)
    session.add(new_todo)
    session.commit()
    session.refresh(new_todo)
    return todo


@app.get("/todos/{id}")
async def getTodo(id: int, current_user: Annotated[User, Depends(current_user)], session: Annotated[Session, Depends(get_Session)]):

    statment = select(Todo).where(Todo.user_id == current_user.id)
    user_todo = session.exec(statment).all()
    matched_todo = next((todo for todo in user_todo if todo.id == id), None)
    if matched_todo:
        return matched_todo
    else:
        raise HTTPException(status_code=401, detail="details not found")


@app.put("/todos/{id}")
async def updateTodo(id: int, todo: Todo_Edit, current_user: Annotated[User, Depends(current_user)], session: Annotated[Session, Depends(get_Session)]):
    statment = select(Todo).where(Todo.user_id == current_user.id)
    user_todo = session.exec(statment).all()
    existing_todo = next((todo for todo in user_todo if todo.id == id), None)
    if existing_todo:
        existing_todo.content = todo.content
        existing_todo.is_completed = todo.is_completed
        session.add(existing_todo)
        session.commit()
        session.refresh(existing_todo)
        return existing_todo
    else:
        raise HTTPException(
            status_code=404, detail="Id is not matched to the existing todos")


@app.delete("/todos/{id}")
async def deleteTodo(id: int, current_user: Annotated[User, Depends(current_user)], session: Annotated[Session, Depends(get_Session)]):
    statment = select(Todo).where(Todo.user_id == current_user.id)
    user_todo = session.exec(statment).all()
    existing_todo = next((todo for todo in user_todo if todo.id == id), None)
    if existing_todo:
        session.delete(existing_todo)
        session.commit()
        return {"message": "Your TOdo has beed deleted"}
    else:
        raise HTTPException(
            status_code=404, detail="Id is not matched to the existing todos")
