import os
import jwt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# FastAPI application instance
app = FastAPI()

# CORS Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, or specify your frontend URL like "http://localhost:3000"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class ContactForm(BaseModel):
    name: str
    email: str
    subject: str
    message: str

class User(BaseModel):
    email: str
    password: str

# Custom JWTBearer class to decode and verify JWT token
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, token: str) -> bool:
        try:
            jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.PyJWTError:
            return False

# Route to handle user signup
@app.post("/signup/")
async def signup(user: User):
    try:
        response = supabase.table("users").insert({
            "email": user.email,
            "password": user.password,  # Ideally, hash the password before saving
        }).execute()

        if response.get("status_code") >= 400 or response.get("error"):
            raise HTTPException(status_code=400, detail="Failed to create user.")

        return {"message": "Signup successful", "user_id": response.get("data")[0].get("id")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Route to handle user login
@app.post("/login/")
async def login(user: User):
    try:
        response = supabase.table("users").select("*").eq("email", user.email).execute()
        users = response.get("data", [])

        if not users or users[0].get("password") != user.password:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        payload = {"email": user.email}
        access_token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")

        return {"message": "Login successful", "access_token": access_token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Protected route example that requires JWT authentication
@app.get("/protected/")
async def protected_route(token: str = Depends(JWTBearer())):
    current_user = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
    return {"message": "You have access", "user": current_user}

# Route to save contact form
@app.post("/contact")
async def save_contact_form(form: ContactForm):
    try:
        response = supabase.table("contact_forms").insert({
            "name": form.name,
            "email": form.email,
            "subject": form.subject,
            "message": form.message,
        }).execute()

        if response.get("status_code") >= 400 or response.get("error"):
            return {"error": "Failed to insert data into Supabase"}

        return {"message": "Message saved successfully", "data": response.get("data")}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}
