import requests
from git import Repo

# Your GitLab host (e.g., https://gitlab.com)
host = "https://gitlab.com"

# Your private token for authentication
token = "my_private_token"

# Your gitlab username
username = "my_username"

# Get the projects/repositories
url = f"{host}/api/v4/projects"
headers = {'PRIVATE-TOKEN': token}
response = requests.get(url, headers=headers)
repositories = response.json()

# Clone each repository
for repo in repositories:
    git_url = f"https://{username}:{token}@{host}/{repo['path_with_namespace']}.git"
    DEST_NAME = repo["path"]
    Repo.clone_from(git_url, DEST_NAME)