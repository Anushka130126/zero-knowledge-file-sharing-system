import os
from datetime import datetime
from typing import AsyncIterator, Optional
from uuid import uuid4

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorDatabase,
    AsyncIOMotorGridFSBucket,
)
from pydantic import BaseModel
from pymongo import ReturnDocument


load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set. Please define it in your .env file.")


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB strict limit
GRIDFS_BUCKET_NAME = "encrypted_blobs"
SHARES_COLLECTION_NAME = "shares"


def _get_db_name_from_uri(uri: str) -> Optional[str]:
    """
    Derive the database name from a MongoDB URI if present.
    Falls back to None if no database portion is found.
    """
    try:
        # Strip query string if present
        base = uri.split("?", 1)[0]
        if "/" not in base:
            return None
        db_name = base.rsplit("/", 1)[1]
        return db_name or None
    except Exception:
        return None


MONGO_DB_NAME = os.getenv("MONGO_DB_NAME") or _get_db_name_from_uri(MONGO_URI) or "zero_trust_storage"


app = FastAPI(title="Zero-Knowledge Storage Broker")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class UploadResponse(BaseModel):
    file_id: str


class FailResponse(BaseModel):
    file_id: str
    failed_attempts: int
    deleted: bool


async def get_db(request: Request) -> AsyncIOMotorDatabase:
    return request.app.state.mongo_db


def get_gridfs_bucket(db: AsyncIOMotorDatabase) -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(db, bucket_name=GRIDFS_BUCKET_NAME)


@app.on_event("startup")
async def startup_event() -> None:
    client = AsyncIOMotorClient(MONGO_URI)
    app.state.mongo_client = client
    app.state.mongo_db = client[MONGO_DB_NAME]


@app.on_event("shutdown")
async def shutdown_event() -> None:
    client: AsyncIOMotorClient = app.state.mongo_client
    client.close()


async def burn_after_reading(file_id: str, gridfs_id: ObjectId, db: AsyncIOMotorDatabase) -> None:
    """
    Background task: permanently delete the GridFS file and its metadata document.
    """
    bucket = get_gridfs_bucket(db)
    try:
        await bucket.delete(gridfs_id)
    except Exception:
        # Intentionally swallow errors here to avoid breaking background execution.
        pass

    await db[SHARES_COLLECTION_NAME].delete_one({"file_id": file_id})


async def gridfs_file_iterator(
    bucket: AsyncIOMotorGridFSBucket,
    gridfs_id: ObjectId
):
    """
    Async iterator that streams a file from GridFS chunk-by-chunk.
    """
    # open_download_stream requires an await in motor to fetch the metadata
    download_stream = await bucket.open_download_stream(gridfs_id)
    while True:
        # readchunk() is Motor's native, highly-optimized streaming method
        chunk = await download_stream.readchunk()
        if not chunk:
            break
        yield chunk


@app.post("/api/upload", response_model=UploadResponse)
async def upload_encrypted_file(
    file: UploadFile = File(...),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> UploadResponse:
    """
    Accept an encrypted blob and stream it directly into GridFS.
    Enforces a strict 10MB limit and creates a metadata document in the shares collection.
    """
    bucket = get_gridfs_bucket(db)
    file_id = str(uuid4())
    total_bytes = 0

    upload_stream = bucket.open_upload_stream(file.filename or file_id)
    try:
        while True:
            chunk = await file.read(1024 * 1024)  # read in 1MB chunks
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_SIZE_BYTES:
                await upload_stream.abort()
                raise HTTPException(
                    status_code=413,
                    detail="File too large. Maximum allowed size is 10MB.",
                )
            await upload_stream.write(chunk)

        gridfs_id = upload_stream._id
    finally:
        await upload_stream.close()
        await file.close()

    metadata = {
        "file_id": file_id,
        "gridfs_id": gridfs_id,
        "failed_attempts": 0,
        "created_at": datetime.utcnow(),
    }
    await db[SHARES_COLLECTION_NAME].insert_one(metadata)

    return UploadResponse(file_id=file_id)


@app.get("/api/download/{file_id}")
async def download_encrypted_file(
    file_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Stream the encrypted blob from GridFS and schedule burn-after-reading cleanup
    as a FastAPI BackgroundTask.
    """
    shares_collection = db[SHARES_COLLECTION_NAME]
    metadata = await shares_collection.find_one({"file_id": file_id})
    if not metadata:
        raise HTTPException(status_code=404, detail="File not found.")

    gridfs_id = metadata.get("gridfs_id")
    if not gridfs_id:
        raise HTTPException(status_code=500, detail="Invalid file metadata.")

    bucket = get_gridfs_bucket(db)

    # Schedule burn-after-reading cleanup to run after the response is sent.
    background_tasks.add_task(burn_after_reading, file_id, gridfs_id, db)

    iterator = gridfs_file_iterator(bucket, gridfs_id)

    return StreamingResponse(
        iterator,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_id}.bin"',
        },
        background=background_tasks,
    )


@app.post("/api/fail/{file_id}", response_model=FailResponse)
async def register_failed_attempt(
    file_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> FailResponse:
    """
    Increment the failed_attempts counter.
    On reaching 3 or more failed attempts, permanently delete the file and metadata.
    """
    shares_collection = db[SHARES_COLLECTION_NAME]

    updated = await shares_collection.find_one_and_update(
        {"file_id": file_id},
        {"$inc": {"failed_attempts": 1}},
        return_document=ReturnDocument.AFTER,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Share not found.")

    failed_attempts = int(updated.get("failed_attempts", 0))
    deleted = False

    if failed_attempts >= 3:
        gridfs_id = updated.get("gridfs_id")
        if gridfs_id:
            bucket = get_gridfs_bucket(db)
            try:
                await bucket.delete(gridfs_id)
            except Exception:
                # Do not prevent metadata deletion if the blob delete fails.
                pass
        await shares_collection.delete_one({"file_id": file_id})
        deleted = True

    return FailResponse(
        file_id=file_id,
        failed_attempts=failed_attempts,
        deleted=deleted,
    )