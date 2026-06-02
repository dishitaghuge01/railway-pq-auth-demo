from flask import Flask, render_template, jsonify
import os

app = Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    return jsonify({'status': 'prs_booking ok'})

@app.route('/ticket')
def ticket():
    return render_template('ticket.html', holder='Alice')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(port=port)
