import pymongo
client = pymongo.MongoClient('mongodb://localhost:27017')
db = client.fraudshield
metrics = list(db.metrics.find())
print('📊 ACTUAL DATABASE METRICS:')
for m in metrics:
    print(f'  {m["_id"]}: {m.get("count", 0)}')
