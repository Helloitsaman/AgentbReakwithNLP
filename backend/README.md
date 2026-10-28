# AgentBreak - FastAPI + MongoDB Atlas Backend

Backend API powered by FastAPI and MongoDB Atlas.

## Setup & Running

1. Ensure Python virtual environment is activated:
   ```powershell
   # If from project root:
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

3. Ensure `.env` is configured with your MongoDB Atlas connection string:
   ```env
   MONGODB_URI=mongodb+srv://...
   DB_NAME=AgentBreak
   COLLECTION_NAME=items
   PORT=8000
   CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
   ```

4. Run the API server:
   ```powershell
   python main.py
   ```

## Endpoints

- `GET  /` - Service info
- `GET  /health` - MongoDB connection ping and collection stats
- `POST /items` - Insert a document into MongoDB
- `GET  /items` - List recent documents from MongoDB
- `GET  /docs` - Interactive Swagger documentation
