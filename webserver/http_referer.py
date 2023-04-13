from flask import Flask, request, redirect

app = Flask(__name__)

app.config.update(
    DEBUG = False,
    SECRET_KEY = 'secret_this_wont_be_important'
)

@app.errorhandler(401)
def custom_401(error):
    return redirect("401 please just stop, thanks")

@app.errorhandler(404)
def custom_404(error):
    return("page not found")

if __name__ == '__main__':
    app.run(host='185.78.255.231', port=80)
