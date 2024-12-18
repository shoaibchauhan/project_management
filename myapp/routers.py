import hashlib
from fastapi import APIRouter, FastAPI, HTTPException, Depends, Header, status
from django.contrib.auth import get_user_model, authenticate
from fastapi.security import OAuth2PasswordBearer
from myapp.models import Project, User, Comment, Task, ProjectMember
from myapp.schema import CommentCreate, CommentResponse, CommentUpdate, ProjectCreate, ProjectResponse, ProjectUpdate, TaskCreate, TaskResponse, TaskUpdate
from myapp.schema import UserRegister, UserLogin, LoginResponse, UserResponse, UserUpdate
import jwt
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import HTTPException
from passlib.hash import bcrypt
from passlib.context import CryptContext
from jose import jwt, JWTError





router = APIRouter()


# Secret key used to encode and decode the JWT token
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2PasswordBearer for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify the JWT token
def verify_access_token(token: str):
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Dependency to extract and validate the JWT token from the Authorization header
def get_current_user(authorization: str = Header(...), token: str = Depends(oauth2_scheme)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization header must start with Bearer"
        )
    token = authorization[7:]  # Remove "Bearer " part to get the token
    return verify_access_token(token)



# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        # If the hash cannot be verified due to an invalid format, return False
        return False

# Hash the password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Function to create JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to verify JWT token
def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Register a new user
@router.post("/api/users/register/", response_model=UserResponse)
def register_user(user: UserRegister):
    # Check if the user already exists by email
    if User.objects.filter(email=user.email).exists():
        raise HTTPException(status_code=400, detail="Email is already registered")
    
    # Hash the password using SHA-256
    hashed_password = hash_password(user.password)
    
    # Create the user object
    user_obj = User.objects.create(
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        password=hashed_password  # Store the hashed password
    )
    
    # Return the created user as a response
    return user_obj

# Login a user and return a token
@router.post("/api/users/login/", response_model=LoginResponse)
def login_user(user: UserLogin):
    # Check if the user exists
    user_obj = User.objects.filter(username=user.username).first()
    if not user_obj:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Verify the password
    if not verify_password(user.password, user_obj.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Create a JWT token
    user_data = {"sub": user_obj.username, "id": user_obj.id}
    access_token = create_access_token(data=user_data)
    
    return LoginResponse(access_token=access_token)

# Retrieve details of a specific user
@router.get("/api/users/{id}/", response_model=UserResponse)
def get_user_details(id: int):
    try:
        user_obj = User.objects.get(id=id)
        return user_obj
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

# Update user details
@router.put("/api/users/{id}/", response_model=UserResponse)
def update_user(id: int, user: UserUpdate):
    try:
        user_obj = User.objects.get(id=id)
        
        # Check if the new email is provided and if it already exists
        if user.email and user.email != user_obj.email:
            if User.objects.filter(email=user.email).exists():
                raise HTTPException(status_code=400, detail="Email is already registered")
        
        # Update fields only if provided
        if user.first_name is not None:
            user_obj.first_name = user.first_name
        if user.last_name is not None:
            user_obj.last_name = user.last_name
        if user.email is not None:
            user_obj.email = user.email
        
        user_obj.save()
        return user_obj
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User  not found")

# Delete a user account
@router.delete("/api/users/{id}/")
def delete_user(id: int):
    try:
        user_obj = User.objects.get(id=id)
        user_obj.delete()
        return {"detail": "User  successfully deleted"}
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")



# List Projects (GET /api/projects/)
@router.get("/api/projects/", response_model=List[ProjectResponse])
def list_projects(token: str = Depends(verify_access_token)):
    projects = Project.objects.all()

    if not projects:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No projects found"
        )

    return projects

# Create Project (POST /api/projects/)
@router.post("/api/projects/", response_model=ProjectResponse)
def create_project(project: ProjectCreate, token: str = Depends(verify_access_token)):
    user_data = token  # This is the decoded token data returned by the dependency
    owner_id = user_data["id"]
    
    # Create the project
    project_obj = Project.objects.create(
        name=project.name,
        description=project.description,
        owner_id=owner_id
    )
    
    return project_obj

# Retrieve Project (GET /api/projects/{id}/)
@router.get("/api/projects/{id}/", response_model=ProjectResponse)
def get_project(id: int, token: str = Depends(verify_access_token)):
    try:
        project = Project.objects.get(id=id)
        return project
    except Project.DoesNotExist:
        raise HTTPException(status_code=404, detail="Project not found")

# Update Project (PUT/PATCH /api/projects/{id}/)
@router.put("/api/projects/{id}/", response_model=ProjectResponse)
@router.patch("/api/projects/{id}/", response_model=ProjectResponse)
def update_project(id: int, project: ProjectUpdate, token: str = Depends(verify_access_token)):
    try:
        project_obj = Project.objects.get(id=id)
        
        # Ensure the user is the owner of the project
        user_data = token  # This is the decoded token data returned by the dependency
        if project_obj.owner_id != user_data["id"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this project")

        if project.name:
            project_obj.name = project.name
        if project.description:
            project_obj.description = project.description

        project_obj.save()
        return project_obj
    except Project.DoesNotExist:
        raise HTTPException(status_code=404, detail="Project not found")

# Delete Project (DELETE /api/projects/{id}/)
@router.delete("/api/projects/{id}/")
def delete_project(id: int, token: str = Depends(verify_access_token)):
    try:
        project_obj = Project.objects.get(id=id)

        # Ensure the user is the owner of the project
        user_data = token  # This is the decoded token data returned by the dependency
        if project_obj.owner_id != user_data["id"]:
            raise HTTPException(status_code=403, detail="Not authorized to delete this project")

        project_obj.delete()
        return {"detail": "Project successfully deleted"}
    except Project.DoesNotExist:
        raise HTTPException(status_code=404, detail="Project not found")


# List Tasks (GET /api/projects/{project_id}/tasks/)
@router.get("/api/projects/{project_id}/tasks/", response_model=List[TaskResponse])
def list_tasks(project_id: int, token: str = Depends(verify_access_token)):
    tasks = Task.objects.filter(project_id=project_id)
    return tasks

# Create Task (POST /api/projects/{project_id}/tasks/)
@router.post("/api/projects/{project_id}/tasks/", response_model=TaskResponse)
def create_task(
    project_id: int, 
    task: TaskCreate, 
    token: str = Depends(verify_access_token)
):
    # Verify that the project exists
    project = Project.objects.filter(id=project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Create the task
    task_obj = Task.objects.create(
        title=task.title,
        description=task.description,
        status=task.status,
        priority=task.priority,
        project_id=project_id,
        assigned_to_id=task.assigned_to_id,
        due_date=task.due_date
    )
    
    # Return the created task
    return task_obj

# Retrieve Task (GET /api/tasks/{id}/)
@router.get("/api/tasks/{id}/", response_model=TaskResponse)
def get_task(id: int, token: str = Depends(verify_access_token)):
    try:
        task = Task.objects.get(id=id)
        return task
    except Task.DoesNotExist:
        raise HTTPException(status_code=404, detail="Task not found")

# Update Task (PUT/PATCH /api/tasks/{id}/)
@router.put("/api/tasks/{id}/", response_model=TaskResponse)
@router.patch("/api/tasks/{id}/", response_model=TaskResponse)
def update_task(id: int, task: TaskUpdate, token: str = Depends(verify_access_token)):
    try:
        task_obj = Task.objects.get(id=id)

        if task.title:
            task_obj.title = task.title
        if task.description:
            task_obj.description = task.description
        if task.status:
            task_obj.status = task.status
        if task.priority:
            task_obj.priority = task.priority
        if task.assigned_to_id:
            task_obj.assigned_to_id = task.assigned_to_id
        if task.due_date:
            task_obj.due_date = task.due_date
        
        task_obj.save()
        return task_obj
    except Task.DoesNotExist:
        raise HTTPException(status_code=404, detail="Task not found")

# Delete Task (DELETE /api/tasks/{id}/)
@router.delete("/api/tasks/{id}/")
def delete_task(id: int, token: str = Depends(verify_access_token)):
    try:
        task_obj = Task.objects.get(id=id)
        task_obj.delete()
        return {"detail": "Task  successfully deleted"}
    except Task.DoesNotExist:
        raise HTTPException(status_code=404, detail="Task not found")


# List Comments (GET /api/tasks/{task_id}/comments/)
@router.get("/api/tasks/{task_id}/comments/", response_model=List[CommentResponse])
def list_comments(task_id: int, token: str = Depends(verify_access_token)):
    comments = Comment.objects.filter(task_id=task_id)
    return comments

# Create Comment (POST /api/tasks/{task_id}/comments/)
@router.post("/api/tasks/{task_id}/comments/", response_model=CommentResponse)
def create_comment(task_id: int, comment: CommentCreate, token: str = Depends(verify_access_token)):
    # At this point, `token` is already decoded and contains user data
    user_data = token  # Use the decoded token directly, no need to call verify_access_token again
    
    # Ensure the task exists
    task = Task.objects.filter(id=task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Create the comment
    comment_obj = Comment.objects.create(
        content=comment.content,
        task_id=task_id,
        user_id=user_data["id"]  # Use user ID from the decoded token
    )
    
    return comment_obj

# Retrieve Comment (GET /api/comments/{id}/)
@router.get("/api/comments/{id}/", response_model=CommentResponse)
def get_comment(id: int, token: str = Depends(verify_access_token)):
    try:
        comment = Comment.objects.get(id=id)
        return comment
    except Comment.DoesNotExist:
        raise HTTPException(status_code=404, detail="Comment not found")

# Update Comment (PUT/PATCH /api/comments/{id}/)
@router.put("/api/comments/{id}/", response_model=CommentResponse)
@router.patch("/api/comments/{id}/", response_model=CommentResponse)
def update_comment(id: int, comment: CommentUpdate, token: str = Depends(verify_access_token)):
    try:
        comment_obj = Comment.objects.get(id=id)

        # Ensure the user is the creator of the comment
        user_data = token  # This is the decoded token data returned by the dependency
        if comment_obj.user_id != user_data["id"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this comment")

        # Update the content if provided
        if comment.content:
            comment_obj.content = comment.content

        comment_obj.save()
        return comment_obj
    except Comment.DoesNotExist:
        raise HTTPException(status_code=404, detail="Comment not found")


# Delete Comment (DELETE /api/comments/{id}/)
@router.delete("/api/comments/{id}/")
def delete_comment(id: int, token: str = Depends(verify_access_token)):
    try:
        comment_obj = Comment.objects.get(id=id)
        comment_obj.delete()
        return {"detail": "Comment  successfully deleted"}
    except Comment.DoesNotExist:
        raise HTTPException(status_code=404, detail="Comment not found")
