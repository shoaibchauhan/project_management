from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

# Register user schema
class UserRegister(BaseModel):
    username:str
    email: EmailStr
    first_name: str
    last_name: str
    password: str

# Login user schema
class UserLogin(BaseModel):
    username: str
    password: str

# Response schema after login with token
class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# User response schema
class UserResponse(BaseModel):
    id: int
    username:str
    email: EmailStr
    first_name: str
    last_name: str
    date_joined: datetime

# Update user schema
class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None



class ProjectBase(BaseModel):
    name: str
    description: str

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(ProjectBase):
    name: Optional[str]
    description: Optional[str]

class ProjectResponse(ProjectBase):
    id: int
    owner: UserResponse
    created_at: datetime

    class Config:
        from_attributes=True

# Task Schema
class TaskBase(BaseModel):
    title: str
    description: str
    status: Optional[str] = 'To Do'
    priority: Optional[str] = 'Low'
    due_date: datetime

class TaskCreate(TaskBase):
    assigned_to_id: Optional[int]

class TaskUpdate(TaskBase):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[datetime] = None
    assigned_to_id: Optional[int]

class TaskResponse(TaskBase):
    id: int
    assigned_to: Optional[UserResponse]
    project: ProjectResponse
    created_at: datetime

    class Config:
        from_attributes=True

# Comment Schema
class CommentBase(BaseModel):
    content: str

class CommentCreate(CommentBase):
    pass

class CommentUpdate(CommentBase):
    content: Optional[str]

class CommentResponse(CommentBase):
    id: int
    user: UserResponse
    task: TaskResponse
    created_at: datetime

    class Config:
        from_attributes=True

# Response Schema for Listing Projects, Tasks, and Comments
class ProjectListResponse(BaseModel):
    projects: List[ProjectResponse]

    class Config:
        from_attributes=True

class TaskListResponse(BaseModel):
    tasks: List[TaskResponse]

    class Config:
        from_attributes=True

class CommentListResponse(BaseModel):
    comments: List[CommentResponse]

    class Config:
        from_attributes=True