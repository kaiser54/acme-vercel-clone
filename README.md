# GitHub Repository Explorer

A simple application that connects to your GitHub account through OAuth, lists all your public and private repositories, and allows you to view repository details and create new commits.

## Features

- Secure authentication with GitHub using OAuth 2.0
- List all your public and private GitHub repositories
- View detailed information about each repository:
  - Primary language
  - Framework detection (React, Vue, Angular, Next.js, Nuxt.js)
  - Preset/template information
  - Recent commits
  - Last update time
- Create new commits directly from the application

## Setup Instructions

1. Clone this repository
   ```
   git clone https://github.com/yourusername/github-repo-explorer.git
   cd github-repo-explorer
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Create a GitHub OAuth App
   - Go to GitHub Settings > Developer settings > OAuth Apps
   - Click "New OAuth App"
   - Fill in the application details:
     - Application name: GitHub Repository Explorer
     - Homepage URL: http://localhost:3000
     - Authorization callback URL: http://localhost:3000/auth/github/callback
   - Click "Register application"
   - After registration, note your Client ID
   - Generate a new client secret and note it down (you'll only see it once)

4. Create a `.env` file in the root directory
   ```
   GITHUB_CLIENT_ID=your_github_oauth_client_id
   GITHUB_CLIENT_SECRET=your_github_oauth_client_secret
   SESSION_SECRET=a_long_random_string_for_securing_sessions
   REDIRECT_URI=http://localhost:3000/auth/github/callback
   PORT=3000  # Optional, defaults to 3000
   ```

5. Start the server
   ```
   npm start
   ```

6. Open your browser and navigate to `http://localhost:3000`

## Project Structure

```
github-repo-explorer/
├── server.js           # Backend Express server with GitHub OAuth
├── public/             # Frontend files
│   └── index.html      # HTML/CSS/JS for the frontend
├── .env                # Environment variables (create this)
├── .env.example        # Example environment file
├── package.json        # Project dependencies
└── README.md           # This file
```

## API Endpoints

### Authentication Endpoints
- `GET /auth/github` - Initiate GitHub OAuth flow
- `GET /auth/github/callback` - GitHub OAuth callback
- `GET /auth/logout` - Logout and destroy session
- `GET /api/user` - Get current authenticated user

### Repository Endpoints
- `GET /api/repos` - Get all repositories
- `GET /api/repos/:owner/:repo` - Get details for a specific repository
- `POST /api/repos/:owner/:repo/commit` - Create a new commit

## Technologies Used

- **Backend:** Node.js, Express
- **Authentication:** GitHub OAuth 2.0
- **API:** GitHub REST API
- **Frontend:** HTML, CSS, JavaScript (Vanilla)
- **HTTP Client:** Axios
- **Session Management:** express-session
- **Environment:** dotenv for environment variables

## Security Considerations

- Uses state parameter to prevent CSRF attacks in OAuth flow
- Stores GitHub access tokens in server-side sessions instead of client storage
- Implements httpOnly cookies for session storage
- Uses secure cookies in production environment
- Authenticates all API endpoints

## License

MIT

## Author

Your Name

---

Feel free to contribute to this project by opening issues or submitting pull requests!# acme-vercel-clone
