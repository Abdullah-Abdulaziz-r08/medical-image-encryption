from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pathlib import Path
from pydantic import BaseModel
from typing import List
import base64

from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential

from database import get_db, init_db, User, Patient, MedicalImage, hash_password, verify_password
from encryption import encrypt, decrypt, compute_hash, bytes_to_array, array_to_bytes

app = FastAPI()

# ===== جلب السيكرت كي من Azure Key Vault =====
_VAULT_URL     = "https://medcrypt-vault-2025.vault.azure.net"
_TENANT_ID     = "514faa19-8c84-4cef-8ae9-2b9dbce933cd"
_CLIENT_ID     = "d136ebca-3d29-41a4-8bad-b4bb7caa6867"
_CLIENT_SECRET = "G~D8Q~r4agRj0E4ce-s9fQ64XRODSWjTdM5xlao8"

def get_secret_key() -> float:
    credential = ClientSecretCredential(
        tenant_id     = _TENANT_ID,
        client_id     = _CLIENT_ID,
        client_secret = _CLIENT_SECRET
    )
    client = SecretClient(vault_url=_VAULT_URL, credential=credential)
    secret = client.get_secret("SECRET-KEY")
    return float(secret.value)

SECRET_KEY = get_secret_key()
app.mount("/static", StaticFiles(directory="templates"), name="static")


@app.on_event("startup")
def startup():
    init_db()


# ===== الصفحات =====
@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(Path("templates/index.html").read_text(encoding="utf-8"))

@app.get("/admin-panel", response_class=HTMLResponse)
def admin_panel():
    return HTMLResponse(Path("templates/admin.html").read_text(encoding="utf-8"))


# ===== تسجيل الدخول =====
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(401, "اسم المستخدم أو كلمة المرور غلط")
    return {"id": user.id, "name": user.name, "role": user.role, "username": user.username}


# ===== نسيت كلمة المرور (بالهوية) =====
class ResetPasswordData(BaseModel):
    username:     str
    national_id:  str
    new_password: str

@app.post("/reset-password")
def reset_password(data: ResetPasswordData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or user.national_id != data.national_id.strip():
        raise HTTPException(401, "اسم المستخدم أو رقم الهوية غير صحيح")
    if len(data.new_password) < 4:
        raise HTTPException(400, "كلمة المرور قصيرة جداً (4 أحرف على الأقل)")
    user.password = hash_password(data.new_password)
    db.commit()
    return {"success": True, "message": "تم تغيير كلمة المرور بنجاح"}


# ===== تغيير كلمة المرور (داخل التطبيق) =====
class ChangePasswordData(BaseModel):
    username:     str
    old_password: str
    new_password: str

@app.post("/change-password")
def change_password(data: ChangePasswordData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.old_password, user.password):
        raise HTTPException(401, "كلمة المرور الحالية غير صحيحة")
    if len(data.new_password) < 4:
        raise HTTPException(400, "كلمة المرور قصيرة جداً")
    user.password = hash_password(data.new_password)
    db.commit()
    return {"success": True, "message": "تم تغيير كلمة المرور بنجاح"}


# ===== المرضى =====
@app.get("/patients")
def get_patients(db: Session = Depends(get_db)):
    patients = db.query(Patient).all()
    return [{"id": p.id, "file_number": p.file_number, "name": p.name,
             "doctors": [{"id": d.id, "name": d.name} for d in p.doctors]} for p in patients]

@app.get("/patients/my/{doctor_id}")
def get_my_patients(doctor_id: int, db: Session = Depends(get_db)):
    doctor = db.query(User).filter(User.id == doctor_id).first()
    if not doctor:
        raise HTTPException(404, "الدكتور غير موجود")
    return [{"id": p.id, "file_number": p.file_number, "name": p.name} for p in doctor.patients]


# ===== رفع صور متعددة =====
@app.post("/upload")
async def upload_images(
    files:       List[UploadFile] = File(...),
    patient_id:  int              = Form(...),
    uploaded_by: str              = Form(...),
    notes:       str              = Form(""),
    db:          Session          = Depends(get_db)
):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(404, "المريض غير موجود")

    for file in files:
        img_bytes        = await file.read()
        img_array        = bytes_to_array(img_bytes)
        img_hash         = compute_hash(img_array)
        encrypted_array  = encrypt(img_array, SECRET_KEY)
        encrypted_base64 = base64.b64encode(array_to_bytes(encrypted_array)).decode()
        db.add(MedicalImage(
            patient_id=patient.id, file_number=patient.file_number,
            patient_name=patient.name, original_hash=img_hash,
            image_data=encrypted_base64, uploaded_by=uploaded_by, notes=notes
        ))

    db.commit()
    return {"success": True, "message": f"تم رفع {len(files)} صورة بنجاح"}


# ===== قائمة الصور =====
@app.get("/images")
def get_images(db: Session = Depends(get_db)):
    imgs = db.query(MedicalImage).order_by(MedicalImage.uploaded_at.desc()).all()
    return [_img_dict(i) for i in imgs]

@app.get("/images/my/{doctor_id}")
def get_my_images(doctor_id: int, db: Session = Depends(get_db)):
    doctor = db.query(User).filter(User.id == doctor_id).first()
    if not doctor:
        raise HTTPException(404, "الدكتور غير موجود")
    pids = [p.id for p in doctor.patients]
    imgs = db.query(MedicalImage).filter(MedicalImage.patient_id.in_(pids))\
             .order_by(MedicalImage.uploaded_at.desc()).all()
    return [_img_dict(i) for i in imgs]

def _img_dict(img):
    return {"id": img.id, "file_number": img.file_number, "patient_name": img.patient_name,
            "uploaded_by": img.uploaded_by, "uploaded_at": img.uploaded_at.strftime("%Y-%m-%d %H:%M"),
            "notes": img.notes}


# ===== جلب الصورة المشفّرة للعرض =====
@app.get("/view/encrypted/{image_id}")
def view_encrypted(image_id: int, db: Session = Depends(get_db)):
    record = db.query(MedicalImage).filter(MedicalImage.id == image_id).first()
    if not record:
        raise HTTPException(404, "الصورة غير موجودة")
    return {
        "image_data":   record.image_data,          # مشفّرة كما هي
        "patient_name": record.patient_name,
        "file_number":  record.file_number,
        "uploaded_by":  record.uploaded_by,
        "uploaded_at":  record.uploaded_at.strftime("%Y-%m-%d %H:%M"),
        "notes":        record.notes
    }


# ===== فك تشفير الصورة =====
@app.get("/view/decrypted/{image_id}")
def view_decrypted(image_id: int, db: Session = Depends(get_db)):
    record = db.query(MedicalImage).filter(MedicalImage.id == image_id).first()
    if not record:
        raise HTTPException(404, "الصورة غير موجودة")
    enc_array = bytes_to_array(base64.b64decode(record.image_data))
    dec_array = decrypt(enc_array, record.original_hash, SECRET_KEY)
    return {
        "image_data":   base64.b64encode(array_to_bytes(dec_array)).decode(),
        "patient_name": record.patient_name,
        "file_number":  record.file_number,
        "uploaded_by":  record.uploaded_by,
        "uploaded_at":  record.uploaded_at.strftime("%Y-%m-%d %H:%M"),
        "notes":        record.notes
    }


# ===== الأدمن =====
@app.get("/admin/users")
def get_users(db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username, "name": u.name, "role": u.role} for u in db.query(User).all()]

@app.get("/admin/doctors")
def get_doctors(db: Session = Depends(get_db)):
    return [{"id": d.id, "name": d.name} for d in db.query(User).filter(User.role == "doctor").all()]


class UserCreate(BaseModel):
    username:    str
    password:    str
    national_id: str
    role:        str
    name:        str

@app.post("/admin/users")
def create_user(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "اسم المستخدم موجود مسبقاً")
    if data.role not in ["admin", "radiology", "doctor"]:
        raise HTTPException(400, "الدور غير صحيح")
    if not data.national_id.strip():
        raise HTTPException(400, "رقم الهوية مطلوب")
    db.add(User(username=data.username, password=hash_password(data.password),
                national_id=data.national_id.strip(), role=data.role, name=data.name))
    db.commit()
    return {"success": True, "message": f"تم إضافة {data.name}"}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "المستخدم غير موجود")
    if user.role == "admin":
        raise HTTPException(400, "لا يمكن حذف حساب الأدمن")
    db.delete(user)
    db.commit()
    return {"success": True, "message": f"تم حذف {user.name}"}


class PatientCreate(BaseModel):
    file_number: str
    name:        str
    doctor_ids:  List[int]

@app.post("/admin/patients")
def create_patient(data: PatientCreate, db: Session = Depends(get_db)):
    if db.query(Patient).filter(Patient.file_number == data.file_number).first():
        raise HTTPException(400, "رقم الملف موجود مسبقاً")
    if not data.doctor_ids:
        raise HTTPException(400, "يجب تحديد دكتور مسؤول")
    doctors = db.query(User).filter(User.id.in_(data.doctor_ids), User.role == "doctor").all()
    if not doctors:
        raise HTTPException(400, "لم يتم العثور على الأطباء")
    db.add(Patient(file_number=data.file_number, name=data.name, doctors=doctors))
    db.commit()
    return {"success": True, "message": f"تم إضافة {data.name}"}

@app.delete("/admin/patients/{patient_id}")
def delete_patient(patient_id: int, db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(404, "المريض غير موجود")
    db.delete(patient)
    db.commit()
    return {"success": True, "message": f"تم حذف {patient.name}"}
