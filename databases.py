from pymongo.mongo_client import MongoClient
from bson.objectid import ObjectId

class Mongo:
    def __init__(self, url) -> None:
        self.client = MongoClient(url)
        self.db = self.client["xorpass"]
    
    def add_user(self,password, email, public_key, private_key):
        self.db["users"].insert_one({
                                    "email": email,
                                    "password":password,
                                    "public_key":public_key,
                                    "private_key":private_key})
    
    def get_user(self, email):
        return self.db["users"].find_one({"email":email})
    
    def add_data(self, website, email, password, owner_id,difficulty):
        self.db["passwords"].insert_one({
            "website":website,
            "email":email,
            "password":password,
            "owner_id":owner_id,
            "difficulty":difficulty})
    
    def get_data(self, owner_id):
        datas = []
        for x in self.db["passwords"].find({"owner_id":owner_id}):
            datas.append(x)
        return datas
    
    def get_by_email(self, email):
        return self.db["passwords"].find_one({"email":email})
    
    def update_user(self, email, data):
        self.db["users"].update_one({"email":email}, {"$set":data})
    
    def get_by_id(self, id):
        return self.db["passwords"].find_one({"_id":ObjectId(id)})
    
    def update_by_id(self, id, data):
        self.db["passwords"].update_one({"_id":ObjectId(id)}, {"$set":data})

    def delete_user(self, username):
        self.db["users"].delete_one({"username":username})
    
    def delete_data(self, id):
        self.db["passwords"].delete_one({"_id":ObjectId(id)})
    