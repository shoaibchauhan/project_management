from django.db import models
from django.contrib.auth.models import AbstractUser

class User(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly defining the id field as primary key
    username = models.CharField(max_length=150, unique=True)  # Ensure username is unique
    email = models.EmailField(unique=True)  # Email should be unique
    password = models.CharField(max_length=255)  # Storing the password (Django handles hashing)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_joined = models.DateTimeField(auto_now_add=True)  # Automatically set when a user is created

    def __str__(self):
        return self.username

# Project Model
class Project(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly defining the id field as primary key
    name = models.CharField(max_length=200)
    description = models.TextField()
    owner = models.ForeignKey(User, related_name="owned_projects", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

# Project Member Model
class ProjectMember(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly defining the id field as primary key
    ADMIN = 'Admin'
    MEMBER = 'Member'
    ROLE_CHOICES = [(ADMIN, 'Admin'), (MEMBER, 'Member')]

    project = models.ForeignKey(Project, related_name="members", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="project_members", on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=MEMBER)

    def __str__(self):
        return f'{self.user.username} in {self.project.name}'

# Task Model
class Task(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly defining the id field as primary key
    TO_DO = 'To Do'
    IN_PROGRESS = 'In Progress'
    DONE = 'Done'
    STATUS_CHOICES = [(TO_DO, 'To Do'), (IN_PROGRESS, 'In Progress'), (DONE, 'Done')]

    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    PRIORITY_CHOICES = [(LOW, 'Low'), (MEDIUM, 'Medium'), (HIGH, 'High')]

    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=TO_DO)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default=LOW)
    assigned_to = models.ForeignKey(User, null=True, blank=True, related_name="tasks", on_delete=models.SET_NULL)
    project = models.ForeignKey(Project, related_name="tasks", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateTimeField()

    def __str__(self):
        return self.title

# Comment Model
class Comment(models.Model):
    id = models.AutoField(primary_key=True)  # Explicitly defining the id field as primary key
    content = models.TextField()
    user = models.ForeignKey(User, related_name="comments", on_delete=models.CASCADE)
    task = models.ForeignKey(Task, related_name="comments", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content[:50]  # Display first 50 chars
