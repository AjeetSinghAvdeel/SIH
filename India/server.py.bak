from fastapi import FastAPI, UploadFile, File
import uvicorn
import os
import main  # <-- this is your existing logic file

app = FastAPI()

@app.post("/wipe")
async def wipe_file(file: UploadFile = File(...)):
    # Save uploaded file temporarily
    file_path = f"temp_{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Call your secure wiping logic from main.py
    try:
        result = main.secure_wipe(file_path)  # <-- adjust if your function has diff name
    except Exception as e:
        result = f"Error: {e}"

    # Clean up (optional: delete temp file if your logic doesn’t already wipe it)
    if os.path.exists(file_path):
        os.remove(file_path)

    return {"status": "success", "message": result}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
