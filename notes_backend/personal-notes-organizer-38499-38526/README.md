# personal-notes-organizer-38499-38526

Backend: FastAPI service providing user authentication and notes CRUD.

Quick start
- Install dependencies: pip install -r notes_backend/requirements.txt
- Run the server (port is managed by the preview environment): fastapi dev notes_backend/src/api/main.py
- Open API docs: /docs

Environment
- Optionally create a .env file in notes_backend/ using .env.example

Authentication
- Prototype in-memory tokens. Obtain a token via POST /auth/signup or /auth/login and send it as:
  Authorization: Bearer <token>

Endpoints summary
- GET /                      Health check
- POST /auth/signup          Create a user, returns access token
- POST /auth/login           Login existing user, returns access token
- POST /notes                Create note (auth required)
- GET  /notes                List notes with pagination and filters (auth required)
  query params:
    - limit: int (1..100, default 20)
    - offset: int (>=0, default 0)
    - q: search text in title/content
    - tag: filter by tag
- GET  /notes/{id}           Retrieve note by id (auth required)
- PUT  /notes/{id}           Update note (auth required)
- DELETE /notes/{id}         Delete note (auth required)

Example requests (curl)
- Signup:
  curl -s -X POST http://localhost:3001/auth/signup -H "Content-Type: application/json" -d '{"email":"a@b.com","password":"secret123"}'
- Login:
  curl -s -X POST http://localhost:3001/auth/login -H "Content-Type: application/json" -d '{"email":"a@b.com","password":"secret123"}'
- Create note:
  curl -s -X POST http://localhost:3001/notes -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"title":"Note","content":"Body","tags":["work"]}'
- List notes:
  curl -s -X GET "http://localhost:3001/notes?limit=10&offset=0&q=note&tag=work" -H "Authorization: Bearer <token>"
