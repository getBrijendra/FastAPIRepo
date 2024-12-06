import jwt
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from .config import SUPABASE_JWT_SECRET
from .service import create_user, authenticate_user

class User(BaseModel):
    email: str
    password: str

app = FastAPI()

# Custom JWTBearer class to decode and verify JWT token
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials  # Return the token
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, token: str) -> bool:
        try:
            # Decode the JWT using the Supabase secret
            payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
            return True  # If decoding succeeds, return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.PyJWTError:
            return False

# Route for user signup
@app.post("/signup/")
async def signup(user: User):
    signup_response = await create_user(user.email, user.password)

    if "error" in signup_response:
        raise HTTPException(status_code=400, detail=signup_response["error"])

    return {"message": "Signup successful", "user_id": signup_response.get("user", {}).get("id")}

# Route for user login
@app.post("/login/")
async def login(user: User):
    auth_response = await authenticate_user(user.email, user.password)

    if "access_token" not in auth_response:
        raise HTTPException(status_code=401, detail="Authentication failed")

    return {
        "message": "Login successful",
        "access_token": auth_response["access_token"],
        "refresh_token": auth_response["refresh_token"]
    }

# Protected route example, with JWTBearer dependency
@app.get("/protected/")
async def protected_route(token: str = Depends(JWTBearer())):
    # The token is automatically validated by the JWTBearer class
    current_user = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
    return {"message": "You have access", "user": current_user}
