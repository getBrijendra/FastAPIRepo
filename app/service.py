import httpx
import jwt
from .config import SUPABASE_URL, SUPABASE_KEY




# Function to create a user in Supabase
async def create_user(email: str, password: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SUPABASE_URL}/auth/v1/signup",
            headers={
                "apikey": SUPABASE_KEY,
            },
            json={"email": email, "password": password}
        )
        
        response_data = response.json()
        
        if response.status_code != 200:
            return {"error": response_data}

        return response_data


# Function to authenticate a user in Supabase and retrieve tokens
async def authenticate_user(email: str, password: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={
                "apikey": SUPABASE_KEY,
            },
            json={"email": email, "password": password}
        )
        
        response_data = response.json()

        if "access_token" in response_data and "refresh_token" in response_data:
            return {
                "access_token": response_data["access_token"],
                "refresh_token": response_data["refresh_token"]
            }
        else:
            return {"error": response_data}

