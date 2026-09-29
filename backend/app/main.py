from fastapi import FastAPI

app = FastAPI(title="WFC - Warsi Fried Chicken API")

@app.get("/health")
def health():
    return {"status": "ok", "brand": "WFC"}
