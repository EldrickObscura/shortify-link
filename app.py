from flask import Flask, render_template, request, jsonify
import pyshorteners

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shorten', methods=['POST'])
def shorten():
    data = request.get_json()
    url = data.get('url')

    # Raccourcir l'URL
    s = pyshorteners.Shortener()
    short_url = s.tinyurl.short(url)

    return jsonify({'shortened_url': short_url})

if __name__ == "__main__":
    app.run(debug=True)
