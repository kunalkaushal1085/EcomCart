import json
from bson import ObjectId

def serialize_objectid(data):
    if isinstance(data, dict):
        return {k: serialize_objectid(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_objectid(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data