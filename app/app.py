from quart import Quart, jsonify, request, render_template
import os, os.path, base64, uuid, re, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from motor.motor_asyncio import AsyncIOMotorClient

class AESManager:
    """
    Class for managing AES encryption

    Powered by ChatGPT
    """
    def __init__(self, key: bytes):
        self.key = key

    async def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    async def decrypt(self, encrypted_text: str) -> str:
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
        
            cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
        
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except: return '1'

app = Quart(__name__)

if not os.path.isfile('aes.key'): # Creating a AES key, if it doesn't exist
    with open('aes.key', 'wb') as f:
        f.write(os.urandom(32))

with open('aes.key', 'rb') as f:
    aes_key = f.read()

aes_manager = AESManager(aes_key)
database = AsyncIOMotorClient('mongodb://mongo:27017/')
posts = database['awbz_database']['posts']

@app.route('/')
async def index():
    return await render_template('index.html')

@app.route('/healthz')
async def healthz():
    return jsonify({'status': 'OK'})

@app.route('/register')
async def register():
    return await render_template('register.html')

@app.route('/create_post')
async def create_post():
    return await render_template('create_post.html')

@app.route('/<id>')
async def posts_by_id(id):
    return await render_template('posts.html')

@app.route('/api/register', methods=['POST'])
async def api_register():
    id = str(uuid.uuid4())
    return jsonify({
        'uuid': id,
        'key': await aes_manager.encrypt(id)
    })

@app.route('/api/create_post', methods=['POST'])
async def api_create_post():
    decrypted_id = await aes_manager.decrypt(request.headers.get('Key', 'lruOFlPTX92rLPljVRbWGcs='))
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', decrypted_id):
        return jsonify({'error': 'invalid key'}), 403

    data = await request.data
    await posts.insert_one({
        'timestamp': time.time(),
        'uuid': decrypted_id,
        'content': data.decode()
    })

    return jsonify({'status': 'ok'})

@app.route('/api/get_posts/<id>', methods=['GET'])
async def api_get_posts(id):
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', id):
        return jsonify({'error': 'invalid uuid'}), 403

    db_results = posts.find({'uuid': id}, {'_id': False, 'uuid': False}).sort({'timestamp': 1})
    results = []

    async for i in db_results:
        results.append(i)

    return results

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
