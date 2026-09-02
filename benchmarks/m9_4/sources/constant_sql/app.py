from flask import Flask

app = Flask(__name__)


@app.get("/health/<ignored>")
def health(ignored):
    return database.execute("select 1")
