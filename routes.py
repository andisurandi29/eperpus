from flask import Flask, Blueprint, request, jsonify, url_for
from models.models import User, DetailUser, Buku, Kategori, Peminjaman, ResetToken, Fakultas, Prodi, db, bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from schemas.schemas import BukuSchema, KategoriSchema, PeminjamanSchema, FakultasSchema, ProdiSchema
from flask_mail import Mail, Message
import random
from datetime import timedelta, datetime
from sqlalchemy.orm import joinedload
import uuid


buku_schema = BukuSchema()
kategori_schema = KategoriSchema()
peminjaman_schema = PeminjamanSchema()
kategori_schema = KategoriSchema()
fakultas_schema = FakultasSchema()
prodi_schema = ProdiSchema()


bp_buku = Blueprint('bp_buku', __name__)
bp_register_user = Blueprint('bp_register_user', __name__)
bp_login_user = Blueprint('bp_login_user', __name__)
bp_peminjaman = Blueprint('bp_peminjaman', __name__)
bp_auth = Blueprint('bp_auth', __name__)
bp_fakultas = Blueprint('bp_fakultas', __name__)
bp_prodi = Blueprint('bp_prodi', __name__)
bp_kategori = Blueprint('bp_kategori', __name__)

mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/eperpus'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app

@bp_register_user.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(
        nama_lengkap=data['nama_lengkap'],
        username=data['username'],
        password=hashed_password,
        level=data['level']
    )

    db.session.add(new_user)
    db.session.commit()

    user_id = new_user.id

    new_detail_user = DetailUser(
        users_id=user_id,
        tempat_lahir=data['tempat_lahir'],
        tgl_lahir=data['tgl_lahir'],
        email=data['email'],
        telp=data['telp'],
        fakultas_id=data['fakultas_id'],
        prodi_id=data['prodi_id']
    )

    db.session.add(new_detail_user)
    db.session.commit()
    
    return jsonify({"success": True,'message': 'Berhasil Mendaftar Akun'})

# Route untuk login user
@bp_login_user.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username, additional_claims={'level': user.level, 'id': user.id, 'username': user.username})
        return jsonify({'success': True,'message': 'Login Berhasil', 'access_token':access_token, 'nama_user':user.nama_lengkap})
    else:
        return jsonify({'success': False,'message': 'Username dan Password Tidak Cocok'})


# Read all buku per halaman
@bp_buku.route('/buku/page/<int:page>', methods=['GET'])
def buku_per_page(page):
    per_page = 12

    buku = Buku.query.paginate(page=page, per_page=per_page, error_out=False)

    total_pages = buku.pages
    current_page = buku.page

    if not buku.items:
        return jsonify({'success': False, 'message': 'Tidak ada data buku pada halaman ini'}), 404

    result = buku_schema.dump(buku.items, many=True)

    return jsonify({
        'success': True,
        'message': 'Berhasil Mendapatkan Data Buku',
        'total_pages': total_pages,
        'current_page': current_page,
        'per_page': per_page,
        'data': result
    })
    
# Create
@bp_buku.route('/buku', methods=['POST'])
@jwt_required()
def tambah_buku():
    data = request.get_json()
    
    # Mendapatkan identitas pengguna dari token JWT
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False,'message': 'Anda tidak memiliki izin untuk menambahkan buku'}), 403

    kategori_id = data['kategori_id']
    if not Kategori.query.get(kategori_id):
        return jsonify({'success': False,'message': 'Kategori tidak valid'}), 400

        
    new_buku = Buku(
        kode_buku=data['kode_buku'],
        judul_buku=data['judul_buku'],
        kategori_id=kategori_id,
        deskripsi=data['deskripsi'],
        penulis=data['penulis'],
        penerbit=data['penerbit'],
        tahun=data['tahun'],
        stok=data['stok'],
        gambar=data['gambar']
    )

    db.session.add(new_buku)
    db.session.commit()

    return jsonify({'success' : True, 'message': 'Berhasil Menambahkan data'})

# Read all
@bp_buku.route('/buku', methods=['GET'])
@jwt_required()
def semua_buku():
    buku = Buku.query.all()
    result = buku_schema.dump(buku, many=True)
    if result:
        return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})
    else:
        return jsonify({'success' : False, 'message': 'Tidak Ada Data'})
    

# Read one
@bp_buku.route('/buku/<id>', methods=['GET'])
def satu_buku(id):
    # Lakukan join antara tabel Buku dan Kategori
    buku = (
        db.session.query(Buku)
        .join(Kategori, Buku.kategori_id == Kategori.id)
        .filter(Buku.id == id)
        .options(joinedload(Buku.kategori))  # Gunakan joinedload untuk menggabungkan hasil join
        .first()
    )
    result = buku_schema.dump(buku)
    if not result:
        return jsonify({'success' : False, 'message': 'Buku tidak ditemukan'}), 404

    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})

# Update
@bp_buku.route('/buku/<id>', methods=['PUT'])
@jwt_required()
def update_buku(id):
    # Mendapatkan identitas pengguna dari token JWT
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success' : False,'message': 'Anda tidak memiliki izin untuk update buku'}), 403
    
    buku = Buku.query.get(id)
    if not buku:
        return jsonify({'success' : False,'message': 'Buku tidak ditemukan'}), 404

    data = request.get_json()

    kategori_id = data.get('kategori_id')
    if kategori_id and not Kategori.query.get(kategori_id):
        return jsonify({'success' : False,'message': 'Kategori tidak valid'}), 400

    buku.judul_buku = data.get('judul_buku', buku.judul_buku)
    buku.kategori_id = kategori_id or buku.kategori_id
    buku.deskripsi = data.get('deskripsi', buku.deskripsi)
    buku.penulis = data.get('penulis', buku.penulis)
    buku.penerbit = data.get('penerbit', buku.penerbit)
    buku.tahun = data.get('tahun', buku.tahun)
    buku.stok = data.get('stok', buku.stok)
    buku.gambar = data.get('gambar', buku.gambar)

    db.session.commit()

    return jsonify({'success' : True,'message': 'Buku Berhasil Diupdate'})

# Delete
@bp_buku.route('/buku/<id>', methods=['DELETE'])
@jwt_required()
def hapus_buku(id):
    # Mendapatkan identitas pengguna dari token JWT
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success' : False,'message': 'Anda tidak memiliki izin untuk menghapus buku'}), 403
    
    buku = Buku.query.get(id)
    if not buku:
        return jsonify({'success' : False,'message': 'Buku tidak ditemukan'}), 404

    db.session.delete(buku)
    db.session.commit()

    return jsonify({'success' : True,'message': 'Buku Berhasil dihapus'})

def generate_random_code(prefix="EP"):
    # Menghasilkan kode unik menggunakan uuid
    random_code = str(uuid.uuid4().hex)[:6].upper()
    return f"{prefix}{random_code}"

# Create
@bp_peminjaman.route('/peminjaman', methods=['POST'])
@jwt_required()
def tambah_peminjaman():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    data = request.get_json()
    # Mendapatkan durasi peminjaman dari request
    durasi_peminjaman = data['durasi_peminjaman']

    # Menghitung tgl_pengembalian berdasarkan tgl_pinjam dan durasi_peminjaman
    tgl_pinjam = datetime.strptime(data['tgl_pinjam'], '%Y-%m-%d')
    tgl_pengembalian = tgl_pinjam + timedelta(days=durasi_peminjaman)
    # Mengubah tgl_pengembalian menjadi string dengan format tanggal
    tgl_pengembalian_str = tgl_pengembalian.strftime('%Y-%m-%d')
    
    kode_peminjaman = generate_random_code()
    
    new_peminjaman = Peminjaman(
        kode_peminjaman=kode_peminjaman,
        user_id=user.id,
        buku_id=data['buku_id'],
        tgl_pinjam=data['tgl_pinjam'],
        tgl_pengembalian=datetime.strptime(tgl_pengembalian_str, '%Y-%m-%d').date(),
        status="pending",
        keterangan="-"
    )

    db.session.add(new_peminjaman)
    db.session.commit()

    return jsonify({'success' : True,'message': 'Peminjaman Berhasil'})

# Read all untuk admin
@bp_peminjaman.route('/admin/peminjaman', methods=['GET'])
@jwt_required()
def semua_peminjaman():
    # Mendapatkan identitas pengguna dari token JWT
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success' : False,'message': 'Anda tidak memiliki izin melihat peminjaman'}), 403
    peminjaman = Peminjaman.query.all()
    result = peminjaman_schema.dump(peminjaman, many=True)
    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})

# Read all for user based on buku_id
@bp_peminjaman.route('/peminjaman/pending', methods=['GET'])
@jwt_required()
def semua_peminjaman_pending():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    peminjaman = (
        db.session.query(Peminjaman)
        .join(Buku)
        .join(Kategori)  # Tambahkan join dengan tabel Kategori
        .filter(Peminjaman.buku_id == Buku.id, Buku.kategori_id == Kategori.id, Peminjaman.user_id == user.id, Peminjaman.status == 'pending')
        .options(joinedload(Peminjaman.buku))  
        .all()
    )

    if not peminjaman:
        return jsonify({'success' : False, 'message': 'Tidak ada data peminjaman'})

    result = peminjaman_schema.dump(peminjaman, many=True)
    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})

# Read all for user based on buku_id
@bp_peminjaman.route('/peminjaman/active', methods=['GET'])
@jwt_required()
def semua_peminjaman_active():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    peminjaman = Peminjaman.query.filter_by(user_id=user.id, status='active').all()
    
    if not peminjaman:
        return jsonify({'success' : False, 'message': 'Tidak ada data peminjaman'})

    result = peminjaman_schema.dump(peminjaman, many=True)
    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})

@bp_peminjaman.route('/peminjaman/selesai', methods=['GET'])
@jwt_required()
def semua_peminjaman_selesai():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    peminjaman = Peminjaman.query.filter_by(user_id=user.id, status='selesai').all()
    
    if not peminjaman:
        return jsonify({'success' : False, 'message': 'Tidak ada data peminjaman'})

    result = peminjaman_schema.dump(peminjaman, many=True)
    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': result})

# Read one
@bp_peminjaman.route('/peminjaman/<id>', methods=['GET'])
@jwt_required()
def satu_peminjaman(id):
    peminjaman = Peminjaman.query.get(id)
    if not peminjaman:
        return jsonify({'success' : False,'message': 'Peminjaman tidak ditemukan'}), 404

    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': peminjaman})

# Update
@bp_peminjaman.route('/peminjaman/<id>', methods=['PUT'])
@jwt_required()
def update_peminjaman(id):
    # Mendapatkan identitas pengguna dari token JWT
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success' : False,'message': 'Anda tidak memiliki izin untuk update peminjaman'}), 403
    peminjaman = Peminjaman.query.get(id)
    if not peminjaman:
        return jsonify({'success' : False, 'message': 'Peminjaman tidak ditemukan'}), 404

    data = request.get_json()

    peminjaman.status = data.get('status', peminjaman.status)
    peminjaman.keterangan = data.get('keterangan', peminjaman.keterangan)

    db.session.commit()

    return jsonify({'success' : True, 'message': 'Berhasil Update'})

# Delete
@bp_peminjaman.route('/peminjaman/<id>', methods=['DELETE'])
@jwt_required()
def hapus_peminjaman(id):
    peminjaman = Peminjaman.query.get(id)
    if not peminjaman:
        return jsonify({'success' : False,'message': 'Peminjaman tidak ditemukan'}), 404

    db.session.delete(peminjaman)
    db.session.commit()

    return jsonify({'success' : True, 'message': 'Berhasil Mendapatkan data', 'result': peminjaman})

@bp_auth.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not bcrypt.check_password_hash(user.password, old_password):
        return jsonify({'success': False, 'message': 'Password lama tidak cocok'}), 400

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    db.session.commit()

    return jsonify({'success': True, 'message': 'Password berhasil diubah'}), 200

def save_reset_token_to_database(user_id, token, expiration):
    expiration_datetime = datetime.utcnow() + timedelta(seconds=expiration)
    
    reset_token = ResetToken(
        user_id=user_id,
        token=token,
        expiration_datetime=expiration_datetime
    )

    db.session.add(reset_token)
    db.session.commit()

@bp_auth.route('/validate-reset-token', methods=['POST'])
def validate_reset_token():
    data = request.get_json()
    username = data.get('username')
    reset_token = data.get('reset_token')

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    # Mengecek apakah reset token valid
    reset_token_entry = ResetToken.query.filter_by(user_id=user.id, token=reset_token).first()

    if not reset_token_entry or reset_token_entry.expiration_datetime < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token reset password tidak valid atau sudah kedaluwarsa'}), 400

    return jsonify({'success': True, 'message': 'Token reset password valid'})

@bp_auth.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    # Mengecek apakah reset token valid
    reset_token_entry = ResetToken.query.filter_by(user_id=user.id, token=reset_token).first()

    if not reset_token_entry or reset_token_entry.expiration_datetime < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token reset password tidak valid atau sudah kedaluwarsa'}), 400

    # Mengupdate password pengguna dengan password baru
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password

    # Menghapus reset token dari database
    db.session.delete(reset_token_entry)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Password berhasil direset'}), 200

@bp_auth.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    user = User.query.filter_by(username=username,email=email).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    # Membuat kode OTP unik
    otp_code = ''.join(str(random.randint(0, 9)) for _ in range(4))

    # Membuat pesan email dengan kode OTP
    subject = 'Reset Password OTP'
    body = f'Gunakan kode berikut untuk mereset password Anda: {otp_code}'
    message = Message(subject, recipients=[user.email], body=body)

    # Mengirim email
    mail.send(message)

    # Menyimpan kode OTP ke database
    save_reset_token_to_database(user.id, otp_code, 300)  # Simpan kode dengan waktu kedaluwarsa 5 menit (300 detik)

    return jsonify({'success': True, 'message': 'Permintaan reset password berhasil. Silakan periksa email Anda.'}), 200
    

@bp_auth.route('/change-email', methods=['POST'])
@jwt_required()
def change_email():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    data = request.get_json()
    new_email = data.get('new_email')

    if User.query.filter_by(email=new_email).first():
        return jsonify({'success': False, 'message': 'Email sudah digunakan'}), 400

    user.email = new_email
    db.session.commit()

    return jsonify({'success': True, 'message': 'Email berhasil diubah'}), 200

@bp_auth.route('/change-telp', methods=['POST'])
@jwt_required()
def change_telp():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404

    data = request.get_json()
    new_telp = data.get('new_telp')

    user.telp = new_telp
    db.session.commit()

    return jsonify({'success': True, 'message': 'Nomor Telepon berhasil diubah'}), 200


# Create, Read, Update, Delete for Kategori
@bp_kategori.route('/kategori', methods=['POST'])
@jwt_required()
def tambah_kategori():
    current_user = get_jwt_identity()
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda bukan admin'}), 403

    data = request.get_json()

    new_kategori = Kategori(
        nama_kategori=data['nama_kategori']
    )

    db.session.add(new_kategori)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Berhasil menambahkan kategori'}), 201

# ...

@bp_kategori.route('/kategori/<id>', methods=['PUT'])
@jwt_required()
def update_kategori(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk mengupdate kategori'}), 403

    kategori = Kategori.query.get(id)
    if not kategori:
        return jsonify({'success': False, 'message': 'Kategori tidak ditemukan'}), 404

    data = request.get_json()

    kategori.nama_kategori = data.get('nama_kategori', kategori.nama_kategori)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Kategori berhasil diupdate'}), 200

@bp_kategori.route('/kategori/<id>', methods=['DELETE'])
@jwt_required()
def hapus_kategori(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk menghapus kategori'}), 403
    
    kategori = Kategori.query.get(id)
    if not kategori:
        return jsonify({'success': False, 'message': 'Kategori tidak ditemukan'}), 404

    # Memeriksa apakah terdapat relasi dengan tabel Buku
    if Buku.query.filter_by(kategori_id=id).first():
        return jsonify({'success': False, 'message': 'Tidak dapat menghapus kategori karena terdapat relasi dengan tabel Buku'}), 400

    # Jika tidak ada relasi, hapus kategori
    db.session.delete(kategori)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Kategori berhasil dihapus'}), 200

# Create, Read, Update, Delete for Fakultas
@bp_fakultas.route('/fakultas', methods=['POST'])
@jwt_required()
def tambah_fakultas():
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk menambahkan fakultas'}), 403

    data = request.get_json()

    new_fakultas = Fakultas(
        nama_fakultas=data['nama_fakultas']
    )

    db.session.add(new_fakultas)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Berhasil menambahkan fakultas'}), 201

# ...

@bp_fakultas.route('/fakultas/<id>', methods=['PUT'])
@jwt_required()
def update_fakultas(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk mengupdate fakultas'}), 403

    fakultas = Fakultas.query.get(id)
    if not fakultas:
        return jsonify({'success': False, 'message': 'Fakultas tidak ditemukan'}), 404

    data = request.get_json()

    fakultas.nama_fakultas = data.get('nama_fakultas', fakultas.nama_fakultas)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Fakultas berhasil diupdate'}), 200

@bp_fakultas.route('/fakultas/<id>', methods=['DELETE'])
@jwt_required()
def hapus_fakultas(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk menghapus fakultas'}), 403
    
    fakultas = Fakultas.query.get(id)
    if not fakultas:
        return jsonify({'success': False, 'message': 'Fakultas tidak ditemukan'}), 404

    # Memeriksa apakah terdapat relasi dengan tabel Prodi
    if Prodi.query.filter_by(fakultas_id=id).first():
        return jsonify({'success': False, 'message': 'Tidak dapat menghapus fakultas karena terdapat relasi dengan tabel Prodi'}), 400

    # Memeriksa apakah terdapat relasi dengan tabel DetailUser (berdasarkan fakultas_id)
    if DetailUser.query.filter_by(fakultas_id=id).first():
        return jsonify({'success': False, 'message': 'Tidak dapat menghapus fakultas karena terdapat relasi dengan tabel DetailUser'}), 400

    # Jika tidak ada relasi, hapus fakultas
    db.session.delete(fakultas)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Fakultas berhasil dihapus'}), 200


# Create, Read, Update, Delete for Prodi
@bp_prodi.route('/prodi', methods=['POST'])
@jwt_required()
def tambah_prodi():
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk menambahkan prodi'}), 403

    data = request.get_json()

    new_prodi = Prodi(
        fakultas_id=data['fakultas_id'],
        nama_prodi=data['nama_prodi']
    )

    db.session.add(new_prodi)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Berhasil menambahkan prodi'}), 201

@bp_prodi.route('/prodi/<id>', methods=['PUT'])
@jwt_required()
def update_prodi(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk mengupdate prodi'}), 403

    prodi = Prodi.query.get(id)
    if not prodi:
        return jsonify({'success': False, 'message': 'Prodi tidak ditemukan'}), 404

    data = request.get_json()

    prodi.nama_prodi = data.get('nama_prodi', prodi.nama_prodi)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Prodi berhasil diupdate'}), 200

@bp_prodi.route('/prodi/<id>', methods=['DELETE'])
@jwt_required()
def hapus_prodi(id):
    current_user = get_jwt_identity()

    # Memeriksa level pengguna, jika bukan admin, mengembalikan pesan kesalahan
    if current_user != 'admin':
        return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk menghapus prodi'}), 403
    
    prodi = Prodi.query.get(id)
    if not prodi:
        return jsonify({'success': False, 'message': 'Prodi tidak ditemukan'}), 404

    # Memeriksa apakah terdapat relasi dengan tabel DetailUser
    if DetailUser.query.filter_by(prodi_id=id).first():
        return jsonify({'success': False, 'message': 'Tidak dapat menghapus prodi karena terdapat relasi dengan tabel DetailUser'}), 400

    # Jika tidak ada relasi, hapus prodi
    db.session.delete(prodi)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Prodi berhasil dihapus'}), 200


# Rute untuk mendapatkan semua data Kategori
@bp_kategori.route('/kategori', methods=['GET'])
def get_all_kategori():
    kategori = Kategori.query.all()
    result = kategori_schema.dump(kategori, many=True)
    return jsonify({'success': True, 'message': 'Berhasil Mendapatkan Data Kategori', 'result': result})

# Rute untuk mendapatkan semua data Fakultas
@bp_fakultas.route('/fakultas', methods=['GET'])
def get_all_fakultas():
    fakultas = Fakultas.query.all()
    result = fakultas_schema.dump(fakultas, many=True)
    return jsonify({'success': True, 'message': 'Berhasil Mendapatkan Data Fakultas', 'result': result})

# Rute untuk mendapatkan semua data Prodi
@bp_prodi.route('/prodi', methods=['GET'])
@jwt_required()
def get_all_prodi():
    prodi = Prodi.query.all()
    result = prodi_schema.dump(prodi, many=True)
    return jsonify({'success': True, 'message': 'Berhasil Mendapatkan Data Prodi', 'result': result})
# Rute untuk mendapatkan semua data Prodi
@bp_prodi.route('/fakultas/<fakultas_id>/prodi/', methods=['GET'])
def get_fakultas_prodi(fakultas_id):
    prodi = Prodi.query.filter_by(fakultas_id=fakultas_id).all()
    result = prodi_schema.dump(prodi, many=True)
    return jsonify({'success': True, 'message': 'Berhasil Mendapatkan Data Prodi', 'result': result})