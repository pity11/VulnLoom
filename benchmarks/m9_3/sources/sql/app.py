from flask import Flask

app = Flask(__name__)


@app.get("/search/<term>")
def search(term):
    return database.execute("select * from products where name = " + term)
