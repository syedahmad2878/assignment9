from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES  # Custom configuration setting
from app.schema import Token  # Import the Token model from our application
from app.utils.common import authenticate_user, create_access_token

# Initialize OAuth2PasswordBearer, a class that FastAPI provides to handle security with OAuth2 Password Flow
# 'tokenUrl' is the endpoint where the client will send the username and password to get the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create an API router object which will be used to register the endpoint(s)
router = APIRouter()

# Define an endpoint for the login that issues access tokens
# This endpoint will respond to POST requests at "/token" and returns data matching the Token model
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
