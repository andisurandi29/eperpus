# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama_lengkap = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(60))
    level = db.Column(db.String(10))

class DetailUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tempat_lahir = db.Column(db.String(50))
    tgl_lahir = db.Column(db.Date)
    email = db.Column(db.String(50))
    telp = db.Column(db.String(15))
    fakultas_id = db.Column(db.Integer, db.ForeignKey('fakultas.id'))
    prodi_id = db.Column(db.Integer, db.ForeignKey('prodi.id'))

class Fakultas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama_fakultas = db.Column(db.String(50))

class Prodi(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fakultas_id = db.Column(db.Integer, db.ForeignKey('fakultas.id'))
    nama_prodi = db.Column(db.String(50))
    

class Kategori(db.Model):
    __tablename__ = 'kategori'
    id = db.Column(db.Integer, primary_key=True)
    nama_kategori = db.Column(db.String(255), nullable=False)
    
    # Menyatakan relasi dengan tabel Buku
    buku = db.relationship('Buku', back_populates='kategori')

class Buku(db.Model):
    __tablename__ = 'buku'
    id = db.Column(db.Integer, primary_key=True)
    kode_buku = db.Column(db.String(255), nullable=False)
    judul_buku = db.Column(db.String(255), nullable=False)
    kategori_id = db.Column(db.Integer, db.ForeignKey('kategori.id'), nullable=False)
    deskripsi = db.Column(db.Text, nullable=True)
    penulis = db.Column(db.String(255), nullable=False)
    penerbit = db.Column(db.String(255), nullable=False)
    tahun = db.Column(db.Integer, nullable=False)
    stok = db.Column(db.Integer, nullable=False)
    gambar = db.Column(db.String(255), nullable=True)
    
    
    # Menyatakan relasi dengan tabel Kategori
    kategori = db.relationship('Kategori', back_populates='buku')
    peminjaman = db.relationship('Peminjaman', back_populates='buku')
    
class Peminjaman(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode_peminjaman = db.Column(db.String(191), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    buku_id = db.Column(db.Integer, db.ForeignKey('buku.id'), nullable=False)
    tgl_pinjam = db.Column(db.Date, nullable=False)
    tgl_pengembalian = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(50), nullable=False)
    keterangan = db.Column(db.Text, nullable=True)
    
    buku = db.relationship('Buku', back_populates='peminjaman')
    
    
class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(128), nullable=False, unique=True)
    expiration_datetime = db.Column(db.DateTime, nullable=False)

    def __init__(self, user_id, token, expiration_datetime):
        self.user_id = user_id
        self.token = token
        self.expiration_datetime = expiration_datetime