Step 1: create .env file  

API_KEY=<your_api_key_here>  
API_SECRET=<your_api_secret_here>  
ENDOR_NAMESPACE=<your_namespace>  

Step 2: run

```
python3 -m venv venv  
source venv/bin/activate  
pip install -r requirements.txt  
```

Step 3:
If you want to create csv for all findings CRITICAL and HIGH then execute:
```
python3 projects_findings.py
```
or 

If you want to create csv for all findings CRITICAL and HIGH for only project with certain tags:
```
python3 projects_findings.py --project_tags="production,staging"
```


