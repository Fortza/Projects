from dotenv import load_dotenv
import os

load_dotenv()

virus_API_KEY = os.getenv("virustotal_API_KEY")

if not virus_API_KEY:
    raise ValueError("VT_API_KEY not found in .env file")