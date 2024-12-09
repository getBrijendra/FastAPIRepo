import httpx
import jwt
from .config import SUPABASE_URL, SUPABASE_KEY

# Function to create a user in Supabase
async def create_user(email: str, password: str):
    """
    Creates a new user in Supabase with the provided email and password.
    
    :param email: The email address of the user to be created
    :param password: The password for the new user
    :return: Response data from Supabase or error message if the request fails
    """
    async with httpx.AsyncClient() as client:
        # Send a POST request to Supabase API to create a new user
        response = await client.post(
            f"{SUPABASE_URL}/auth/v1/signup",
            headers={
                "apikey": SUPABASE_KEY,
            },
            json={"email": email, "password": password}
        )
        
        # Parse the JSON response data
        response_data = response.json()
        
        # Check if the request was successful
        if response.status_code != 200:
            return {"error": response_data}

        return response_data

# Function to authenticate a user in Supabase and retrieve tokens
async def authenticate_user(email: str, password: str):
    """
    Authenticates a user using email and password and retrieves the access and refresh tokens.
    
    :param email: The email address of the user
    :param password: The password of the user
    :return: Access and refresh tokens or error message if authentication fails
    """
    async with httpx.AsyncClient() as client:
        # Send a POST request to Supabase API to authenticate the user
        response = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={
                "apikey": SUPABASE_KEY,
            },
            json={"email": email, "password": password}
        )
        
        # Parse the JSON response data
        response_data = response.json()

        # Check if the response contains tokens
        if "access_token" in response_data and "refresh_token" in response_data:
            return {
                "access_token": response_data["access_token"],
                "refresh_token": response_data["refresh_token"]
            }
        else:
            # If tokens are not found, return error response
            return {"error": response_data}
