from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import FRONTEND_URL
from service.auth.endpoint import router as auth_router
from service.profile.endpoint import router as profile_router
from service.admin.endpoint import router as admin_router

app = FastAPI(title="Git-Agent API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,  # Required for httpOnly cookies
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],
)

app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(admin_router)