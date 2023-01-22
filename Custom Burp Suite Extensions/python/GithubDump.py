import requests
import git

# Get the repositories
token = "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"
headers = {'Authorization': 'token ' + token}
response = requests.get('https://api.github.com/user/repos', headers=headers)
repositories = response.json()

# Clone each repository
for repo in repositories:
    full_name = repo["full_name"]
    HTTPS_REMOTE_URL = f'https://{token}:x-oauth-basic@github.com/{full_name}.git'
    DEST_NAME = full_name.split('/')[-1]
    git.Repo.clone_from(HTTPS_REMOTE_URL, DEST_NAME)