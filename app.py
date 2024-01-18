from flask import Flask, jsonify
from routes import bp_register_user, bp_login_user, bp_buku, bp_auth, bp_prodi, bp_peminjaman, bp_fakultas, bp_kategori
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from models.models import db
from flask_mail import Mail
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/eperpus'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'ADSSGHJXTTRRTUEEHHHJXBazffxvxbxnkeetewcVQJQK4353642@#'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# Inisialisasi Flask-Mail
mail = Mail()
mail.init_app(app)

db.init_app(app)
jwt = JWTManager(app)
CORS(app)
# Fungsi untuk menangani token yang kedaluwarsa
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'success': False, 'message': 'token_expired'}), 401

# Registrasi blueprint rute
app.register_blueprint(bp_register_user)
app.register_blueprint(bp_login_user)
app.register_blueprint(bp_buku)
app.register_blueprint(bp_auth)
app.register_blueprint(bp_kategori)
app.register_blueprint(bp_fakultas)
app.register_blueprint(bp_prodi)
app.register_blueprint(bp_peminjaman)

# Fungsi untuk membuat tabel-tabel
def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    # Membuat tabel-tabel saat aplikasi dijalankan
    create_tables()
    app.run(debug=True)
