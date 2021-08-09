from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import jwt
import datetime
from functools import wraps
import bcrypt
from flask_cors import CORS



app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'mysecret'

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.fullstack   # select the database
books = db.Books1 # select the collection title
users = db.users    # select the collection title
blacklist = db.blacklist

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify( { 'message' : 'token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify( { 'message' : 'token is invalid' } ), 401
        bl_token = blacklist.find_one( { "token" : token })
        if bl_token is not None:
            return make_response( jsonify( { "message" : "Token has been cancelled"}), 401)
        return func(*args, **kwargs)
    return jwt_required_wrapper

def admin_required(func):
        @wraps(func)
        def admin_required_wrapper(*args, **kwargs):
            token = request.headers['x-access-token']
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if data ["admin"]:
                return func(*args, **kwargs)
            else:
                return make_response( jsonify( { "message" : "Admin access is required"}), 401)
        return admin_required_wrapper

@app.route("/add_review_ids", methods = ["GET"])
def add_new_review_ids():
    output = ""
    for book in books.find():
        new_reviews = []
        for review in book["review"]:
            new_review = {
                "_id" : ObjectId(),
                "username" : review["username"],
                "comment" : review["comment"]
            }
            new_reviews.append(new_review)
        books.update_one( { "_id" : book["_id"] },
                           { "$set" : {"review" : new_reviews} } )
        output = output + "book" + str(book["_id"] ) + "updated <br>"
    return make_response(output)

@app.route("/api/v1.0/books", methods=["GET"])
def show_all_books():
    page_num, page_size = 1, 1000
    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = page_size * (page_num - 1)

    data_to_return = []
    for book in books.find({}, 
    {"title": 1, "country":1, "language":1, "year":1, "pages":1, "link":1, "author":1, "imageLink":1}
    ).skip(page_start).limit(page_size):
        book ["_id"] =str(book["_id"])
        data_to_return.append(book)

    return make_response( jsonify( data_to_return ), 200 )

@app.route("/api/v1.0/books/<string:id>", methods=["GET"])
def show_one_book(id):
    book = books.find_one(
        {"_id":ObjectId(id)},
        {"title": 1, "country":1, "language":1, "year":1, "pages":1, "link":1, "author":1, "reviews":1, "imageLink" :1}
        )
    if book is not None:
        book["_id"] = str(book["_id"])
        for review in book["reviews"]:
            review["_id"] = str(review["_id"])
        return make_response( jsonify( book ), 200 )
    else:
        return make_response ( jsonify( { "error" : "Invalidbook ID" } ), 404 )

@app.route("/api/v1.0/books", methods=["POST"])
def add_book():
    if "title" in request.form and "country" in request.form and "language" in request.form and "year" in request.form and "pages" in request.form and "author" in request.form and "link" in request.form and "imageLink" in request.form:
        new_book = { 
            "title" : request.form["title"],
            "country" : request.form["country"],
            "language" : request.form["language"],
            "year" : request.form["year"],
            "pages" : request.form["pages"],
            "link" : request.form["link"],
            "imageLink" : request.form["imageLink"],
            "author" : request.form["author"],
            "reviews" : []
            
        }
        new_book_id = books.insert_one(new_book)
        new_book_link = "http://localhost:5000/api/v1.0/books/" + str(new_book_id.inserted_id)
        return make_response( jsonify( { "url" : new_book_link } ), 201 )
    else:
        return make_response ( jsonify( { "error" : "Missing form data" } ), 404 )

@app.route("/api/v1.0/books/<string:id>", methods=["PUT"])
def edit_book(id):
    if "title" in request.form and "country" in request.form and "language" in request.form and "year" in request.form and "pages" in request.form and "author" in request.form:
        result = books.update_one(
            {"_id" : ObjectId(id)},
            {
                "$set" : {
                    "title" : request.form["title"],
                    "country" : request.form["country"],
                    "language" : request.form["language"],
                    "year" : request.form["year"],
                    "pages" : request.form["pages"],
                    "author" : request.form["author"]
                }
            }
        )
        if result.matched_count == 1:
            edited_book_link = "http://localhost:5000/api/v1.0/books/" + id
            return make_response( jsonify( { "url" : edited_book_link} ), 200 )
        else:
            return make_response ( jsonify( { "error" : "Invalidbook ID" } ), 404 )
    else:
        return make_response ( jsonify( { "error" : "Missing form data" } ), 404 )


@app.route("/api/v1.0/books/<string:id>", methods=["DELETE"])

def delete_book(id):
    result = books.delete_one({ "_id" : ObjectId(id)})
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204)
    else:
        return make_response ( jsonify( { "error" : "Invalidbook ID" } ), 404 )

@app.route("/api/v1.0/books/<string:id>/reviews", methods=["POST"])
def add_new_review(id):
    new_review = { 
        "_id" : ObjectId(),
        "username" : request.form["username"],
        "comment" : request.form["comment"],
        "stars" : request.form["stars"]
        
     }
    books.update_one( { "_id" : ObjectId(id) } , { "$push" : {"reviews" : new_review }})
    new_review_link = "http://localhost:5000/api/v1.0/books/" + id + "/reviews/" + str(new_review["_id"])
    return make_response( jsonify( { "url" : new_review_link } ), 200 )

@app.route("/api/v1.0/books/<string:id>/review", methods=["GET"])
def fetch_all_reviews(id):
    data_to_return = []
    book = books.find_one( { "_id" : ObjectId(id) }, { "reviews" : 1, "_id" : 0})
    for review in book["reviews"]:
        review["_id"] = str(review["_id"])
        data_to_return.append(review)
    return make_response( jsonify( data_to_return ), 200 )

@app.route("/api/v1.0/books/<string:id>/review/<string:review_id>", methods=["GET"])
def fetch_one_review(id, review_id):
    book = books.find_one( { "reviews._id" : ObjectId(review_id) }, \
        { "_id" :  0, "reviews.$" : 1})
    if book is None:
        return make_response(jsonify ( { "error" : "invalidbook or Review ID"}), 404)
    book ["reviews"] [0] ["_id"] = str(book["reviews"][0]["_id"])
    return make_response( jsonify(book["reviews"][0]) ,200)

@app.route("/api/v1.0/books/<string:book_id>/review/<string:review_id>", methods=["PUT"])
def edit_review(book_id, review_id): 
    edited_review = {
        "reviews.$username" : request.form["username"],
        "reviews.$comment" : request.form["comment"],
        "reviews.$stars" : request.form["stars"]
    }
    books.update_one( \
        { "reviews._id" : ObjectId(review_id) }, { "$set" : edited_review})
    edit_review_url = "http://localhost:5000/api/v1.0/books/" + id + "/reviews/" + review_id
    return make_response( jsonify( { "url" : edit_review_url} ), 200)

@app.route("/api/v1.0/books/<string:book_id>/reviews/<string:review_id>", methods=["DELETE"])

def delete_review(book_id, review_id):
    books.update_one( \
       { "_id" : ObjectId(id) }, \
           {"$pull" : { "reviews" : {"_id" : ObjectId(review_id) } } } )                

    return make_response( jsonify( {} ), 204)

@app.route("/api/v1.0/login", methods=["GET"])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one( { "username" : auth.username } )
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):
                token = jwt.encode( {
                    'user' : auth.username,
                    'admin' : user["admin"],
                    'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                
                }, app.config['SECRET_KEY'])
                return make_response( jsonify( { 'token' : token.decode('UTF-8') }), 200)
            else:
                return make_response( jsonify( {"message" : "Bad password"} ), 401 )
        else:
            return make_response( jsonify( {"message" : "Bad username"} ), 401 )

    return make_response( jsonify( { "message" : "Authentication required"} ), 401 )

@app.route("/api/v1.0/logout", methods=["GET"])

def logout():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return make_response( jsonify( {"message" : "Token is missing" } ), 401)
    else:
        blacklist.insert_one( { "token" : token} )
        return make_response( jsonify( {"message" : "Logout successful"} ), 200 )

if __name__ == "__main__":
    app.run(debug=True)