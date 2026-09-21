from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from Pipeline import process_event, process_events

app = FastAPI(
    title="ULPF API",
    description="Universal Log Pre-processing Framework API",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "Universal Log Pre-processing Framework",
        "status": "operational",
        "version": "1.0"
    }


@app.post("/process")
def process_single_event(event: dict):
    return process_event(event)


@app.post("/process/batch")
def process_batch(events: dict):
    return process_events(events["events"])
