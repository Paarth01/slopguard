from fastapi import FastAPI

app = FastAPI()

@app.get("/admin/users")
def list_users():
    return get_all_users()

@app.get("/profile")
def get_profile(current_user=Depends(get_current_user)):
    return current_user
