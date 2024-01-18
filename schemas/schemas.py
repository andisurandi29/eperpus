from marshmallow import Schema, fields

class KategoriSchema(Schema):
    id = fields.Integer(dump_only=True)
    nama_kategori = fields.String(required=True)

class BukuSchema(Schema):
    id = fields.Integer(dump_only=True)
    kode_buku = fields.String(required=True)
    judul_buku = fields.String(required=True)
    kategori_id = fields.Integer(required=True)
    deskripsi = fields.String()
    penulis = fields.String(required=True)
    penerbit = fields.String(required=True)
    tahun = fields.Integer(required=True)
    stok = fields.Integer(required=True)
    gambar = fields.String()
    
    kategori = fields.Nested('KategoriSchema')


class PeminjamanSchema(Schema):
    id = fields.Integer(dump_only=True)
    kode_peminjaman = fields.String(required=True)
    user_id = fields.Integer(required=True)
    buku_id = fields.Integer(required=True)
    tgl_pinjam = fields.Date(required=True)
    tgl_pengembalian = fields.Date()
    status = fields.String(required=True)
    keterangan = fields.String()
    
    buku = fields.Nested('BukuSchema')
    
# Schema untuk Fakultas
class FakultasSchema(Schema):
    id = fields.Int(dump_only=True)
    nama_fakultas = fields.Str(required=True)

# Schema untuk Prodi
class ProdiSchema(Schema):
    id = fields.Int(dump_only=True)
    nama_prodi = fields.Str(required=True)