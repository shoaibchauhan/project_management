import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project_management.settings')
django.setup()


from fastapi import FastAPI
from myapp import routers

app = FastAPI()
app.include_router(routers.router)


@app.get("/")
def root():
    return {"message": "hello"}