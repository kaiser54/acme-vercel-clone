// server.js - Backend Server with GitHub OAuth, WebSockets and Automatic Webhooks
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const session = require('express-session');
const crypto = require('crypto');
const querystring = require('querystring');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;

// Required environment variables
const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/auth/github/callback`;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET; // Secret for GitHub webhooks

// GitHub API endpoints
const GITHUB_API = 'https://api.github.com';
const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';

// Store user connections
const userConnections = new Map(); // userId -> socket

// In-memory storage for connected repositories
// In a production environment, this should be stored in a database
const connectedRepos = new Map(); // userId -> [repoIds]

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.json()); // For webhook payload parsing
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
app.use(express.static('public'));

// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('New client connected');
    
    // Associate socket with user
    socket.on('register', (userId) => {
        if (userId) {
            console.log(`User ${userId} registered with socket`);
            userConnections.set(userId, socket);
            
            // Listen for client disconnection to remove from map
            socket.on('disconnect', () => {
                console.log(`User ${userId} disconnected`);
                userConnections.delete(userId);
            });
        }
    });
});

// Verify GitHub webhook signature
function verifyWebhookSignature(req) {
    if (!WEBHOOK_SECRET) {
        console.warn('No webhook secret configured, skipping signature verification');
        return true;
    }
    
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
        return false;
    }
    
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const computedSignature = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');
    
    return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(computedSignature)
    );
}

// GitHub webhook endpoint
app.post('/api/webhooks/github', (req, res) => {
    try {
        // Verify the webhook signature
        if (!verifyWebhookSignature(req)) {
            console.error('Invalid webhook signature');
            return res.status(401).send('Invalid signature');
        }
        
        // Get the event type
        const event = req.headers['x-github-event'];
        const payload = req.body;
        
        console.log(`Received GitHub webhook: ${event}`);
        
        // Process different events
        switch (event) {
            case 'push':
                handlePushEvent(payload);
                break;
            case 'create':
                // Branch or tag created
                if (payload.ref_type === 'branch') {
                    handleBranchCreateEvent(payload);
                }
                break;
            case 'delete':
                // Branch or tag deleted
                if (payload.ref_type === 'branch') {
                    handleBranchDeleteEvent(payload);
                }
                break;
            case 'repository':
                // Repository created, deleted, or made public/private
                handleRepositoryEvent(payload);
                break;
            case 'installation_repositories':
                // Repositories added or removed from GitHub App installation
                handleInstallationRepositoriesEvent(payload);
                break;
            case 'installation':
                // GitHub App installation added or removed
                handleInstallationEvent(payload);
                break;
        }
        
        res.status(200).send('Webhook received');
    } catch (error) {
        console.error('Error processing webhook:', error);
        res.status(500).send('Error processing webhook');
    }
});

// Handle push event
function handlePushEvent(payload) {
    const repoFullName = payload.repository.full_name;
    const repoId = payload.repository.id;
    const branch = payload.ref.replace('refs/heads/', '');
    const pusher = payload.pusher.name;
    const commits = payload.commits;
    
    // Find all users with access to this repo and send updates
    for (const [userId, socket] of userConnections.entries()) {
        socket.emit('repo-update', {
            type: 'push',
            repo: {
                id: repoId,
                fullName: repoFullName,
                name: payload.repository.name
            },
            branch,
            commits,
            pusher
        });
    }
}

// Handle branch create event
function handleBranchCreateEvent(payload) {
    const repoFullName = payload.repository.full_name;
    const repoId = payload.repository.id;
    const branch = payload.ref;
    
    for (const [userId, socket] of userConnections.entries()) {
        socket.emit('repo-update', {
            type: 'branch-created',
            repo: {
                id: repoId,
                fullName: repoFullName,
                name: payload.repository.name
            },
            branch
        });
    }
}

// Handle branch delete event
function handleBranchDeleteEvent(payload) {
    const repoFullName = payload.repository.full_name;
    const repoId = payload.repository.id;
    const branch = payload.ref;
    
    for (const [userId, socket] of userConnections.entries()) {
        socket.emit('repo-update', {
            type: 'branch-deleted',
            repo: {
                id: repoId,
                fullName: repoFullName,
                name: payload.repository.name
            },
            branch
        });
    }
}

// Handle repository events
function handleRepositoryEvent(payload) {
    const repoFullName = payload.repository.full_name;
    const repoId = payload.repository.id;
    const action = payload.action; // created, deleted, publicized, privatized
    
    for (const [userId, socket] of userConnections.entries()) {
        socket.emit('repo-update', {
            type: 'repository',
            action,
            repo: {
                id: repoId,
                fullName: repoFullName,
                name: payload.repository.name,
                description: payload.repository.description,
                isPrivate: payload.repository.private,
                updatedAt: payload.repository.updated_at,
                language: payload.repository.language
            }
        });
    }
}

// Handle installation events (for GitHub Apps)
function handleInstallationEvent(payload) {
    if (payload.action === 'created') {
        // New installation created
        console.log('New GitHub App installation created');
    } else if (payload.action === 'deleted') {
        // Installation deleted
        console.log('GitHub App installation deleted');
    }
}

// Handle installation_repositories events
function handleInstallationRepositoriesEvent(payload) {
    if (payload.action === 'added') {
        // Repositories added to installation
        payload.repositories_added.forEach(repo => {
            console.log(`Repository added to installation: ${repo.full_name}`);
        });
    } else if (payload.action === 'removed') {
        // Repositories removed from installation
        payload.repositories_removed.forEach(repo => {
            console.log(`Repository removed from installation: ${repo.full_name}`);
        });
    }
}

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.accessToken) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized', redirectTo: '/auth/github' });
};

// Route to initiate GitHub OAuth flow
app.get('/auth/github', (req, res) => {
    // Generate a random state parameter to prevent CSRF attacks
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;
    
    const authUrl = `${GITHUB_AUTH_URL}?${querystring.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        state: state,
        scope: 'repo read:user admin:repo_hook'  // Added admin:repo_hook for webhook creation
    })}`;
    
    res.redirect(authUrl);
});

// GitHub OAuth callback route
app.get('/auth/github/callback', async (req, res) => {
    const { code, state } = req.query;
    
    // Verify state parameter to prevent CSRF attacks
    if (!state || state !== req.session.oauthState) {
        return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
    }
    
    try {
        // Exchange the authorization code for an access token
        const tokenResponse = await axios.post(GITHUB_TOKEN_URL, {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            code: code,
            redirect_uri: REDIRECT_URI
        }, {
            headers: {
                'Accept': 'application/json'
            }
        });
        
        const accessToken = tokenResponse.data.access_token;
        
        // Store the token in the session
        req.session.accessToken = accessToken;
        
        // Get user data and store in session
        const userResponse = await axios.get(`${GITHUB_API}/user`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        req.session.user = {
            id: userResponse.data.id,
            login: userResponse.data.login,
            name: userResponse.data.name,
            avatar_url: userResponse.data.avatar_url
        };
        
        // Redirect to the main application
        res.redirect('/');
    } catch (error) {
        console.error('Error authenticating with GitHub:', error.message);
        res.status(500).send('Authentication failed. Please try again.');
    }
});

// Logout route
app.get('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

// Route to check if user is authenticated and get user info
app.get('/api/user', (req, res) => {
    if (req.session.user && req.session.accessToken) {
        res.json(req.session.user);
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

// Route to get all repositories (public and private)
app.get('/api/repos', isAuthenticated, async (req, res) => {
    try {
        const accessToken = req.session.accessToken;
        
        const response = await axios.get(`${GITHUB_API}/user/repos?per_page=100&sort=updated`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        const repositories = response.data.map(repo => ({
            id: repo.id,
            name: repo.name,
            fullName: repo.full_name,
            description: repo.description,
            isPrivate: repo.private,
            url: repo.html_url,
            updatedAt: repo.updated_at,
            language: repo.language
        }));
        
        res.json(repositories);
    } catch (error) {
        console.error('Error fetching repositories:', error.message);
        res.status(500).json({ error: 'Failed to fetch repositories' });
    }
});

// New route to connect repositories
app.post('/api/connect-repos', isAuthenticated, async (req, res) => {
    try {
        const { repositories } = req.body;
        const userId = req.session.user.id;
        const accessToken = req.session.accessToken;
        
        if (!repositories || !Array.isArray(repositories)) {
            return res.status(400).json({ error: 'Invalid repositories list' });
        }
        
        // Store the connected repositories
        if (!connectedRepos.has(userId)) {
            connectedRepos.set(userId, []);
        }
        
        const results = [];
        
        // Process each repository
        for (const repo of repositories) {
            try {
                const { owner, name, id } = repo;
                
                // Skip if already connected
                if (connectedRepos.get(userId).includes(id)) {
                    results.push({
                        id,
                        name,
                        owner,
                        status: 'already_connected',
                        message: 'Repository already connected'
                    });
                    continue;
                }
                
                // Create webhook for the repository
                const webhookUrl = `${req.protocol}://${req.get('host')}/api/webhooks/github`;
                
                // Check if webhook already exists
                const hooksResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${name}/hooks`, {
                    headers: {
                        'Authorization': `token ${accessToken}`,
                        'Accept': 'application/vnd.github.v3+json'
                    }
                });
                
                // Look for our webhook
                const existingHook = hooksResponse.data.find(hook => 
                    hook.config && hook.config.url === webhookUrl
                );
                
                let hookId;
                
                if (existingHook) {
                    hookId = existingHook.id;
                    console.log(`Webhook already exists for ${owner}/${name}`);
                } else {
                    // Create a new webhook
                    const newHookResponse = await axios.post(`${GITHUB_API}/repos/${owner}/${name}/hooks`, {
                        name: 'web',
                        active: true,
                        events: ['push', 'create', 'delete', 'repository'],
                        config: {
                            url: webhookUrl,
                            content_type: 'json',
                            secret: WEBHOOK_SECRET
                        }
                    }, {
                        headers: {
                            'Authorization': `token ${accessToken}`,
                            'Accept': 'application/vnd.github.v3+json'
                        }
                    });
                    
                    hookId = newHookResponse.data.id;
                    console.log(`Created webhook for ${owner}/${name}`);
                }
                
                // Add to connected repositories
                connectedRepos.get(userId).push(id);
                
                results.push({
                    id,
                    name,
                    owner,
                    status: 'connected',
                    hookId,
                    message: 'Repository connected successfully'
                });
            } catch (error) {
                console.error(`Error connecting repository ${repo.owner}/${repo.name}:`, error.message);
                results.push({
                    id: repo.id,
                    name: repo.name,
                    owner: repo.owner,
                    status: 'error',
                    message: `Failed to connect: ${error.message}`
                });
            }
        }
        
        res.json({
            success: true,
            results
        });
    } catch (error) {
        console.error('Error connecting repositories:', error.message);
        res.status(500).json({ error: 'Failed to connect repositories' });
    }
});

// New route to get connected repositories
app.get('/api/connected-repos', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const userRepos = connectedRepos.get(userId) || [];
    
    res.json({
        connected: userRepos
    });
});

// Route to get repository details
app.get('/api/repos/:owner/:repo', isAuthenticated, async (req, res) => {
    try {
        const { owner, repo } = req.params;
        const accessToken = req.session.accessToken;
        
        // Get repo details
        const repoResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        // Get commits
        const commitsResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/commits?per_page=5`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        // Get branches
        const branchesResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/branches`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        // Get package.json to determine framework/preset
        let frameworkInfo = { framework: 'N/A', preset: 'N/A' };
        try {
            const packageResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/contents/package.json`, {
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            if (packageResponse.data && packageResponse.data.content) {
                const packageJson = JSON.parse(Buffer.from(packageResponse.data.content, 'base64').toString());
                const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
                
                // Detect framework
                if (dependencies.react) frameworkInfo.framework = 'React';
                else if (dependencies.vue) frameworkInfo.framework = 'Vue';
                else if (dependencies.angular) frameworkInfo.framework = 'Angular';
                else if (dependencies.next) frameworkInfo.framework = 'Next.js';
                else if (dependencies.nuxt) frameworkInfo.framework = 'Nuxt.js';
                
                // Detect preset/template
                if (packageJson.preset) frameworkInfo.preset = packageJson.preset;
                if (packageJson.template) frameworkInfo.preset = packageJson.template;
            }
        } catch (error) {
            console.log('No package.json found or unable to access it');
        }

        const repoDetails = {
            id: repoResponse.data.id,
            name: repoResponse.data.name,
            fullName: repoResponse.data.full_name,
            description: repoResponse.data.description,
            isPrivate: repoResponse.data.private,
            url: repoResponse.data.html_url,
            language: repoResponse.data.language,
            defaultBranch: repoResponse.data.default_branch,
            createdAt: repoResponse.data.created_at,
            updatedAt: repoResponse.data.updated_at,
            framework: frameworkInfo.framework,
            preset: frameworkInfo.preset,
            branches: branchesResponse.data.map(branch => ({
                name: branch.name,
                isDefault: branch.name === repoResponse.data.default_branch
            })),
            lastCommits: commitsResponse.data.map(commit => ({
                sha: commit.sha,
                message: commit.commit.message,
                author: commit.commit.author.name,
                date: commit.commit.author.date,
                url: commit.html_url
            }))
        };
        
        res.json(repoDetails);
    } catch (error) {
        console.error('Error fetching repository details:', error.message);
        res.status(500).json({ error: 'Failed to fetch repository details' });
    }
});

// New route to disconnect a repository
app.delete('/api/repos/:owner/:repo/webhook', isAuthenticated, async (req, res) => {
    try {
        const { owner, repo } = req.params;
        const accessToken = req.session.accessToken;
        const userId = req.session.user.id;
        
        // Find the webhook
        const hooksResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/hooks`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        const webhookUrl = `${req.protocol}://${req.get('host')}/api/webhooks/github`;
        const existingHook = hooksResponse.data.find(hook => 
            hook.config && hook.config.url === webhookUrl
        );
        
        if (existingHook) {
            // Delete the webhook
            await axios.delete(`${GITHUB_API}/repos/${owner}/${repo}/hooks/${existingHook.id}`, {
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            // Remove from connected repositories
            if (connectedRepos.has(userId)) {
                // Find the repo ID
                const repoResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}`, {
                    headers: {
                        'Authorization': `token ${accessToken}`,
                        'Accept': 'application/vnd.github.v3+json'
                    }
                });
                
                const repoId = repoResponse.data.id;
                connectedRepos.set(
                    userId, 
                    connectedRepos.get(userId).filter(id => id !== repoId)
                );
            }
            
            res.json({
                success: true,
                message: 'Repository disconnected successfully'
            });
        } else {
            res.status(404).json({
                error: 'Webhook not found'
            });
        }
    } catch (error) {
        console.error('Error disconnecting repository:', error.message);
        res.status(500).json({ error: 'Failed to disconnect repository' });
    }
});

// Route to create a new commit
app.post('/api/repos/:owner/:repo/commit', isAuthenticated, async (req, res) => {
    try {
        const { owner, repo } = req.params;
        const { filePath, content, message, branch } = req.body;
        const accessToken = req.session.accessToken;

        if (!filePath || !content || !message) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Get the latest commit SHA for the branch
        const refResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/git/ref/heads/${branch || 'main'}`, {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        // Get the current file (if it exists)
        let existingSha;
        try {
            const fileResponse = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}/contents/${filePath}`, {
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                },
                params: {
                    ref: branch || 'main'
                }
            });
            existingSha = fileResponse.data.sha;
        } catch (error) {
            console.log('File does not exist yet or cannot be accessed');
        }

        // Create or update the file
        const updateResponse = await axios.put(
            `${GITHUB_API}/repos/${owner}/${repo}/contents/${filePath}`,
            {
                message,
                content: Buffer.from(content).toString('base64'),
                sha: existingSha,
                branch: branch || 'main'
            },
            {
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            }
        );

        res.json({
            success: true,
            commit: {
                sha: updateResponse.data.commit.sha,
                message,
                url: updateResponse.data.commit.html_url
            }
        });
    } catch (error) {
        console.error('Error creating commit:', error.message);
        res.status(500).json({ error: 'Failed to create commit' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// Serve the frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`GitHub OAuth callback URL: ${REDIRECT_URI}`);
});