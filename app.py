import os
import shutil
import uuid
import asyncio
import json
import httpx
import aiofiles
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any

app = FastAPI(title="APK Malware Analysis")

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory storage for tasks
# Structure: {task_id: {"status": "processing", "step": "Uploading...", "result": None, "error": None}}
TASKS: Dict[str, Any] = {}

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Configuration
MOBSF_API_KEY = ""
MOBSF_URL = ""
VT_API_KEY = ""
GEMINI_API_KEY = ""
OLLAMA_URL = ""

# --------------------------------------------------------------------------------
# Helper Services
# --------------------------------------------------------------------------------

# Helper for File Access
async def retry_open(path, mode='rb', retries=5, delay=1.0):
    """Retries opening a file to handle Windows file locking issues."""
    last_err = None
    for i in range(retries):
        try:
            return open(path, mode)
        except OSError as e:
            last_err = e
            # If access denied or invalid argument, wait and retry
            print(f"File access warning ({i+1}/{retries}): {e}. Retrying...")
            await asyncio.sleep(delay)
    raise last_err

async def analyze_with_mobsf(file_path: str, api_key: str = MOBSF_API_KEY, server_url: str = MOBSF_URL):
    """Uploaded file to MobSF and returns the filtered report."""
    if not api_key: api_key = MOBSF_API_KEY
    if not server_url: server_url = MOBSF_URL
    
    # Use simple abspath to avoid pathlib complexities on Windows OneDrive
    abs_path = os.path.abspath(file_path)
    
    if not os.path.exists(abs_path):
        raise Exception(f"File not found at: {abs_path}")

    async with httpx.AsyncClient() as client:
        # 1. Upload File
        filename = os.path.basename(abs_path)
        
        try:
            # Retry opening file
            f_handle = await retry_open(abs_path, 'rb')
            with f_handle as f:
                # 'application/octet-stream' is safer generic type
                files = {'file': (filename, f, 'application/octet-stream')}
                try:
                    response = await client.post(f"{server_url}/api/v1/upload", headers={'Authorization': api_key}, files=files, timeout=60.0)
                except httpx.ConnectError:
                    raise Exception(f"Could not connect to MobSF at {server_url}. Is it running?")
        except Exception as e:
             raise Exception(f"File Access Error during Upload: {e}")
        
        if response.status_code != 200:
            raise Exception(f"MobSF Upload Failed: {response.text}")
        
        data = response.json()
        scan_hash = data['hash']
        
        # 2. Scan File (if not already scanned)
        scan_response = await client.post(f"{server_url}/api/v1/scan", headers={'Authorization': api_key}, data={'hash': scan_hash}, timeout=120.0)
        if scan_response.status_code != 200:
            raise Exception(f"MobSF Scan Failed: {scan_response.text}")
            
        # 3. Get Report
        report_response = await client.post(f"{server_url}/api/v1/report_json", headers={'Authorization': api_key}, data={'hash': scan_hash}, timeout=30.0)
        if report_response.status_code != 200:
            raise Exception(f"MobSF Report Failed: {report_response.text}")
        
        full_report = report_response.json()
        
        # Filter strictly as requested
        keys_to_keep = [
            "app_name", "package_name", "version_name", "permissions", 
            "malware_permissions", "certificate_analysis", "manifest_analysis",
            "network_security", "android_api", "code_analysis", "urls", 
            "domains", "secrets", "appsec"
        ]
        
        filtered_report = {k: full_report.get(k) for k in keys_to_keep}
        return filtered_report, scan_hash

async def analyze_with_virustotal(file_path: str, api_key: str = VT_API_KEY):
    """Uploads file to VirusTotal and waits for analysis."""
    abs_path = os.path.abspath(file_path)
    
    if not os.path.exists(abs_path):
         raise Exception(f"File not found: {abs_path}")
    
    async with httpx.AsyncClient() as client:
        # User requested to FORCE NEW UPLOAD (No Hash Check)
        filename = os.path.basename(abs_path)
        
        try:
             # Retry opening file
            f_handle = await retry_open(abs_path, 'rb')
            with f_handle as f:
                files = {'file': (filename, f)}
                resp = await client.post("https://www.virustotal.com/api/v3/files", headers={'x-apikey': api_key}, files=files, timeout=120.0)
        except Exception as e:
            raise Exception(f"VT File Access Error: {e}")
        
        if resp.status_code != 200:
            raise Exception(f"VirusTotal Upload Failed: {resp.text}")
            
        analysis_id = resp.json()['data']['id']
        
        # Poll for results
        for _ in range(90): # Try for 3 minutes
            status_resp = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers={'x-apikey': api_key})
            status_data = status_resp.json()
            status = status_data['data']['attributes']['status']
            
            if status == 'completed':
                return status_data['data']['attributes']
            
            await asyncio.sleep(2)
            
        return {"status": "timeout", "message": "Analysis pending on VirusTotal", "analysis_id": analysis_id}

async def analyze_with_llm(context_data: dict, provider: str, api_key: str, model: str):
    """Sends the context to the selected LLM. Returns (result_text, prompt_used)."""
    if not api_key and provider == 'gemini': api_key = GEMINI_API_KEY
    
    # --- Token Optimization Strategy ---
    
    # 1. Optimize VirusTotal Data
    vt_data = context_data.get('virustotal', {})
    if 'stats' in vt_data:
        stats = vt_data['stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        total_engines = malicious + suspicious + undetected + harmless
        if malicious == 0 and suspicious == 0:
            vt_summary = f"CLEAN ({malicious}/{total_engines} engines detected malware). 0 Suspicious."
        else:
            vt_summary = f"INFECTED/SUSPICIOUS ({malicious}/{total_engines} engines detected malware). {suspicious} Suspicious."
    elif 'error' in vt_data:
        vt_summary = f"Error: {vt_data['error']}"
    else:
        vt_summary = "Analysis Not Completed / Timeout"

    # 2. Optimize MobSF Data (Aggressive Filtering)
    mobsf = context_data.get('mobsf', {})
    
    # PERMISSIONS: Only list names of dangerous permissions
    all_perms = mobsf.get('permissions', {})
    dangerous_perms = [p for p, details in all_perms.items() if details.get('status') == 'dangerous']
    if not dangerous_perms and all_perms:
        dangerous_perms = list(all_perms.keys())[:5] # Fallback to top 5 if no dangerous ones

    # SECRETS: Top 3 only
    secrets = mobsf.get('secrets', [])[:3]
    
    # MALWARE PERMISSIONS: Summary only
    malware_perms_data = mobsf.get('malware_permissions', {})
    top_malware_perms = malware_perms_data.get('top_malware_permissions', [])

    # CODE ANALYSIS & ANDROID API: Keys only (Remove file lists)
    # This is the biggest token saver. We only send "detected features" like "api_camera", "api_crypto" etc.
    android_api = mobsf.get('android_api', {})
    detected_apis = list(android_api.keys()) if android_api else []
    
    code_analysis = mobsf.get('code_analysis', {}).get('findings', {})
    code_findings = []
    for key, value in code_analysis.items():
        if value and isinstance(value, dict):
             # Extract metadata info if available, or just use key
             severity = value.get('metadata', {}).get('severity', 'info')
             if severity in ['high', 'warning']: # Only send High/Warning findings
                 code_findings.append(f"{key} ({severity})")

    # MANIFEST: Titles only
    manifest_findings = []
    for f in mobsf.get('manifest_analysis', {}).get('manifest_findings', []):
        if f.get('severity') in ['high', 'warning']:
            manifest_findings.append(f"{f.get('title')} ({f.get('severity')})")

    # DOMAINS: Only Bad ones
    all_domains = mobsf.get('domains', {})
    bad_domains = [d for d, info in all_domains.items() if info.get('bad') == 'yes']

    # Construct Dynamic Prompt
    app_info = f"Name: {mobsf.get('app_name', 'N/A')}, Pkg: {mobsf.get('package_name', 'N/A')}"
    
    # User requested FULL raw data for VT
    vt_full_results = vt_data.get('results', {})
    
    prompt_parts = [
        "You are a Malware Analyst. Classify APK as MALICIOUS/BENIGN/SUSPICIOUS depending on risk.",
        "IMPORTANT: If VirusTotal result is CLEAN (0 detections), you should strictly lean towards BENIGN unless there are critical hardcoded secrets or backdoors.",
        f"1. APP: {app_info}",
        f"2. VIRUSTOTAL SUMMARY: {vt_summary}",
        f"2.1 VIRUSTOTAL FULL RESULTS: {json.dumps(vt_full_results)}" 
    ]
    
    if dangerous_perms:
        prompt_parts.append(f"3. DANGEROUS PERS: {json.dumps(dangerous_perms)}")
        
    if top_malware_perms:
        prompt_parts.append(f"4. MALWARE SIGS: {json.dumps(top_malware_perms)}")
        
    if secrets:
        prompt_parts.append(f"5. SECRETS (Sample): {json.dumps(secrets)}")
        
    if detected_apis:
        # Just top 10 interesting APIs to save space
        interesting_apis = [api for api in detected_apis if 'crypto' in api or 'exec' in api or 'network' in api or 'location' in api]
        if interesting_apis:
            prompt_parts.append(f"6. RISKY APIS: {json.dumps(interesting_apis)}")
            
    if code_findings:
        prompt_parts.append(f"7. CODE ISSUES: {json.dumps(code_findings)}")

    if manifest_findings:
        prompt_parts.append(f"8. MANIFEST ISSUES: {json.dumps(manifest_findings)}")

    if bad_domains:
        prompt_parts.append(f"9. BAD DOMAINS: {json.dumps(bad_domains)}")
        
    prompt_parts.append("\nGive succinct verdict & reason.")
    
    prompt = "\n".join(prompt_parts)

    try:
        if provider == "gemini":
            # STRICTLY enforce 1.5-Flash to avoid quota issues with 2.0 or Pro
            # We ignore the 'model' param if it's not a flash model, to be safe.
            candidates = ["gemini-1.5-flash", "gemini-1.5-flash-001", "gemini-1.5-flash-8b"]
            
            # Remove duplicates
            seen = set()
            fallback_models = [x for x in candidates if not (x in seen or seen.add(x))]

            async with httpx.AsyncClient() as client:
                last_error = None
                for m in fallback_models:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={api_key}"
                    payload = {"contents": [{"parts": [{"text": prompt}]}]}
                    
                    # Retry Count per model for 429 errors
                    max_retries = 2
                    
                    for attempt in range(max_retries + 1):
                        try:
                            resp = await client.post(url, json=payload, timeout=60.0)
                            
                            # Handle 429 Rate Limit specifically
                            if resp.status_code == 429:
                                if attempt < max_retries:
                                    wait_time = (attempt + 1) * 5 
                                    print(f"Rate limited on {m}. Waiting {wait_time}s...")
                                    await asyncio.sleep(wait_time)
                                    continue
                                else:
                                    error_data = resp.json()
                                    last_error = f"{m} (Rate Limit Exceeded): {error_data.get('error', {}).get('message', resp.text)}"
                                    break 
                            
                            elif resp.status_code == 200:
                                result = resp.json()
                                try:
                                    text_resp = result['candidates'][0]['content']['parts'][0]['text']
                                    return (f"**Model Used: {m}**\n\n{text_resp}", prompt)
                                except:
                                    return ("Error parsing Gemini response.", prompt)
                            else:
                                error_data = resp.json()
                                last_error = f"{m}: {error_data.get('error', {}).get('message', resp.text)}"
                                break 
                        except Exception as e:
                            last_error = str(e)
                            break
                    
                    await asyncio.sleep(1)
                
                return (f"All Gemini models failed. Last error: {last_error}", prompt)

        elif provider == "ollama":
            url = f"{OLLAMA_URL}/api/generate"
            payload = {"model": model, "prompt": prompt, "stream": False}
            async with httpx.AsyncClient() as client:
                try:
                    resp = await client.post(url, json=payload, timeout=120.0)
                except httpx.ConnectError:
                    return (f"Could not connect to Ollama at {OLLAMA_URL}. Is it running?", prompt)
                    
                if resp.status_code != 200:
                    return (f"Ollama Error: {resp.text}", prompt)
                return (resp.json()['response'], prompt)
                
        return ("Unknown Provider", prompt)
    except Exception as e:
        return (f"Critical AI Error: {str(e)}", prompt)

# --------------------------------------------------------------------------------
# Background Worker
# --------------------------------------------------------------------------------

async def process_analysis(task_id: str, file_path: str, mobsf_key: str, vt_key: str, llm_provider: str, llm_key: str, llm_model: str):
    try:
        # Wait a moment for file handle to release fully
        await asyncio.sleep(1)
        
        report = {}
        
        # Step 1: MobSF
        TASKS[task_id]['step'] = "Analyzing with MobSF..."
        try:
            mobsf_data, _ = await analyze_with_mobsf(file_path, mobsf_key)
            report['mobsf'] = mobsf_data
        except Exception as e:
            print(f"MobSF Error: {e}")
            report['mobsf'] = {"error": str(e)}

        # Step 2: VirusTotal
        TASKS[task_id]['step'] = "Scanning with VirusTotal..."
        try:
            vt_data = await analyze_with_virustotal(file_path, vt_key)
            report['virustotal'] = vt_data
        except Exception as e:
            print(f"VT Error: {e}")
            report['virustotal'] = {"error": str(e)}
            
        # Step 3: LLM (Even if others failed, we try to get an explanation or summary)
        TASKS[task_id]['step'] = f"Consulting {llm_provider.capitalize()} AI..."
        
        # Always get the prompt back!
        ai_response, debug_prompt = await analyze_with_llm(report, llm_provider, llm_key, llm_model)
        
        print(f"DEBUG: AI Response Length: {len(str(ai_response))}")
        print(f"DEBUG: Prompt Length: {len(str(debug_prompt))}")

        report['ai_analysis'] = ai_response
        report['debug_prompt_content'] = debug_prompt # Renamed for verification
        
        # --- DATA CLEANUP FOR USER DISPLAY ---
        # The user requested to clean the raw JSON to avoid confusion and large size.
        if 'mobsf' in report:
            m = report['mobsf']
            # Remove the massive API file lists
            m.pop('android_api', None)
            # Remove file lists from code analysis findings
            if 'code_analysis' in m and 'findings' in m['code_analysis']:
                for k, v in m['code_analysis']['findings'].items():
                    if isinstance(v, dict) and 'files' in v:
                        v.pop('files', None) # Remove detailed file paths
            # Limit secrets in display
            if 'secrets' in m and isinstance(m['secrets'], list):
                m['secrets'] = m['secrets'][:5] # Show only top 5 secrets
        
        print("DEBUG: Report keys:", report.keys())



        TASKS[task_id]['result'] = report
        TASKS[task_id]['status'] = "completed"
        TASKS[task_id]['step'] = "Done"
        
    except Exception as e:
        TASKS[task_id]['status'] = "failed"
        TASKS[task_id]['error'] = str(e)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Cleanup Error: {e}")

# --------------------------------------------------------------------------------
# API Endpoints
# --------------------------------------------------------------------------------

@app.get("/")
async def index():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    mobsf_key: str = Form(""),
    vt_key: str = Form(""),
    llm_provider: str = Form("gemini"), # gemini or ollama
    llm_key: str = Form(""),
    llm_model: str = Form("gemini-1.5-flash")
):
    task_id = str(uuid.uuid4())
    # Save with a purely synthetic name on disk to avoid ANY Windows path issues
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}.apk")
    
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
        
    TASKS[task_id] = {
        "status": "processing",
        "step": "Initializing...",
        "created_at": task_id
    }
    
    background_tasks.add_task(
        process_analysis, 
        task_id, 
        file_path, 
        mobsf_key, 
        vt_key, 
        llm_provider, 
        llm_key, 
        llm_model
    )
    
    return {"task_id": task_id}

@app.get("/api/status/{task_id}")
async def get_status(task_id: str):
    task = TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "status": task['status'],
        "step": task.get('step', ''),
        "error": task.get('error')
    }

@app.get("/api/result/{task_id}")
async def get_result(task_id: str):
    task = TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task['status'] != 'completed':
         raise HTTPException(status_code=400, detail="Analysis not ready")
    
    return task['result']

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
