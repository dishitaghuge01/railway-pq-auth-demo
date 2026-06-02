from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({'status': 'cris_signer ok'})

if __name__ == '__main__':
    app.run(port=5001)
