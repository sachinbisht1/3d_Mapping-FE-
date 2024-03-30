![Botlab Dynamics Logo](https://botlabdynamics.com/sites/default/files/2022-11/BL%20Botlab%20Dynamics%20%281%29.png)

# 3d_mapping
Generate 3D Maps using aerial photos and videos

# Required packages to setup project
1. [Ubuntu 22.04](https://releases.ubuntu.com/jammy/)
2. [Python3](https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tar.xz) 
3. [Python3 virtualenv](https://pypi.org/project/virtualenv/)
4. npm (10.5.0)

# Project setup
1. `git clone https://github.com/BotLabDynamics/3d_mapping.git`
2. `cd 3d_mapping`
3. `python3 -m venv venv`
4. `source .venv/bin/activate`
5. `pip install -r requirements.dev.txt`

# Setup Dynamodb locally
> [!NOTE]
> Set up dynamodb locally on local environment rather then hitting aws dynamodb.

1. > Install docker on your system
2. `docker pull amazon/dynamodb-local`
3. `docker run -itd -p 8000:8000  --name dev-db amazon/dynamodb-local:latest -jar DynamoDBLocal.jar -sharedDb`
4. `npm install -g dynamodb-admin`
5. `dynamodb-admin`

> [!NOTE]
> Set dynamodb endpoint to url provided by dynamodb docker

# Running 3d_mapping FastApi server
`uvicorn backend.main:app --port 8080 --reload`

# Project Layout
-   > Controllers - Where we will manage logic by using various gateways
-   > gateways - All api wriiten in this folder using their base library
-   > constants.py - All global constants will be defined in this file
-   > test_* - It is used to test our code before continuous deployment
