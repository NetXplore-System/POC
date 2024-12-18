from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from dotenv import load_dotenv
from database import db
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
import os

# Load environment variables
load_dotenv()
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)
print("API RUNNING")
researchers = db["researcher"]  # Access the 'researcher' collection


# Pydantic Models
class ResearcherCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class ResearcherResponse(BaseModel):
    id: str
    name: str
    email: EmailStr


class ResearcherSignIn(BaseModel):
    password: str
    email: EmailStr


# Utility Function to Convert MongoDB Document
def document_to_response(doc):
    return {"id": str(doc["_id"]), "name": doc["name"], "email": doc["email"]}


@app.post("/researchers/signin", response_model=ResearcherResponse)
async def signin(data: ResearcherSignIn):
    user = await researchers.find_one({"email": data.email})
    if not user or not bcrypt.checkpw(data.password.encode('utf-8'), user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return document_to_response(user)
    
# Create a Researcher
@app.post("/researchers", response_model=ResearcherResponse)
async def create_researcher(researcher: ResearcherCreate):
    existing = await researchers.find_one({"email": researcher.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = bcrypt.hashpw(researcher.password.encode('utf-8'), bcrypt.gensalt())
    new_researcher = {
        "name": researcher.name,
        "email": researcher.email,
        "password": hashed_password.decode('utf-8')
    }
    result = await researchers.insert_one(new_researcher)
    return {"id": str(result.inserted_id), "name": researcher.name, "email": researcher.email}


# Get All Researchers
@app.get("/researchers", response_model=list[ResearcherResponse])
async def get_all_researchers():
    researcher_list = await researchers.find().to_list(100)
    return [document_to_response(researcher) for researcher in researcher_list]

# Get a Researcher by ID
@app.get("/researchers/{id}", response_model=ResearcherResponse)
async def get_researcher(id: str):
    try:
        researcher = await researchers.find_one({"_id": ObjectId(id)})
        if not researcher:
            raise HTTPException(status_code=404, detail="Researcher not found")
        return document_to_response(researcher)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")

# Update a Researcher
@app.put("/researchers/{id}", response_model=ResearcherResponse)
async def update_researcher(id: str, updates: ResearcherCreate):
    try:
        updated_data = {k: v for k, v in updates.dict().items() if v is not None}
        if "password" in updated_data:
            updated_data["password"] = bcrypt.hashpw(updated_data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        result = await researchers.update_one({"_id": ObjectId(id)}, {"$set": updated_data})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Researcher not found")
        researcher = await researchers.find_one({"_id": ObjectId(id)})
        return document_to_response(researcher)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")


# Delete a Researcher
@app.delete("/researchers/{id}")
async def delete_researcher(id: str):
    try:
        result = await researchers.delete_one({"_id": ObjectId(id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Researcher not found")
        return {"message": "Researcher deleted successfully"}
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")
    
