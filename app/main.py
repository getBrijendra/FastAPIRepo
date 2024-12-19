import jwt
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from .config import SUPABASE_JWT_SECRET
from .service import create_user, authenticate_user

# Pydantic model for User input validation
class User(BaseModel):
    email: str
    password: str

# FastAPI application instance
app = FastAPI()

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        """
        Initialize the JWTBearer class.
        :param auto_error: If True, automatically raises HTTPException on authorization failure.
        """
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        """
        Retrieve the JWT token from the request and validate it.
        :param request: Incoming request
        :return: JWT token if valid, raises HTTPException otherwise
        """
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):  # Call verify_jwt here
                raise HTTPException(status_code=403, detail="Invalid or expired token.")
            return credentials.credentials  # Return valid token
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, token: str) -> bool:
        """
        Verify the JWT token by decoding it using the provided secret.
        :param token: JWT token to verify
        :return: True if the token is valid, False if it is expired or invalid
        """
        try:
            # Decode the JWT token using the Supabase JWT secret
            jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False}  # Disable audience verification
            )
            return True  # Token is valid
        except jwt.ExpiredSignatureError:
            return False  # Token has expired
        except jwt.InvalidTokenError:
            return False  # Token is invalid




# Route to handle user signup
@app.post("/signup/")
async def signup(user: User):
    """
    Endpoint to register a new user.
    :param user: User model containing email and password
    :return: Success message and user ID on successful signup
    """
    signup_response = await create_user(user.email, user.password)

    # Check if there is an error in signup response
    if "error" in signup_response:
        raise HTTPException(status_code=400, detail=signup_response["error"])

    return {"message": "Signup successful", "user_id": signup_response.get("user", {}).get("id")}

# Route to handle user login
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


@app.get("/protected/")
async def protected_route(token: str = Depends(JWTBearer())):
    # Decode the token to retrieve user information
    current_user = jwt.decode(
        token, 
        SUPABASE_JWT_SECRET, 
        algorithms=["HS256"], 
        options={"verify_aud": False}
    )
    return {"message": "You have access", "user": current_user}

