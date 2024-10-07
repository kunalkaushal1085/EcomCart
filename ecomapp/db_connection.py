# from pymongo import MongoClient
import pymongo


from django.conf import settings


def get_db_handle():
    client = pymongo.MongoClient(
        host=settings.MONGO_DB_HOST,
        port=settings.MONGO_DB_PORT,
        # username=settings.MONGO_DB_USER,
        # password=settings.MONGO_DB_PASSWORD
    )
    db_handle = client[settings.MONGO_DB_NAME]
    return db_handle, client
