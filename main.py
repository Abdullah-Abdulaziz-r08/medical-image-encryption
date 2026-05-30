from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional
import base64
import os
from dotenv import load_dotenv

from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential

load_dotenv()

from database import (get_db, init_db, User, Patient, MedicalImage,
                      hash_password, verify_password, validate_password,
                      generate_file_number)
from encryption import encrypt, decrypt, compute_hash, bytes_to_array, array_to_bytes

app = FastAPI()

# ===== Azure Key Vault =====
_VAULT_URL     = os.getenv("AZURE_VAULT_URL")
_TENANT_ID     = os.getenv("AZURE_TENANT_ID")
_CLIENT_ID     = os.getenv("AZURE_CLIENT_ID")
_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

def get_secret_key() -> float:
    credential = ClientSecretCredential(
        tenant_id=_TENANT_ID, client_id=_CLIENT_ID, client_secret=_CLIENT_SECRET)
    client = SecretClient(vault_url=_VAULT_URL, credential=credential)
    return float(client.get_secret("SECRET-KEY").value)

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

# ===== استعادة كلمة المرور =====
class ResetPasswordData(BaseModel):
    username:     str
    national_id:  str
    new_password: str

@app.post("/reset-password")
def reset_password(data: ResetPasswordData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or user.national_id != data.national_id.strip():
        raise HTTPException(401, "اسم المستخدم أو رقم الهوية غير صحيح")
    err = validate_password(data.new_password)
    if err:
        raise HTTPException(400, err)
    user.password = hash_password(data.new_password)
    db.commit()
    return {"success": True, "message": "تم تغيير كلمة المرور بنجاح"}

# ===== المرضى =====
@app.get("/patients")
def get_patients(db: Session = Depends(get_db)):
    return [{"id": p.id, "file_number": p.file_number, "name": p.name,
             "doctors": [{"id": d.id, "name": d.name} for d in p.doctors]}
            for p in db.query(Patient).all()]

@app.get("/patients/my/{doctor_id}")
def get_my_patients(doctor_id: int, db: Session = Depends(get_db)):
    doctor = db.query(User).filter(User.id == doctor_id).first()
    if not doctor:
        raise HTTPException(404, "الدكتور غير موجود")
    return [{"id": p.id, "file_number": p.file_number, "name": p.name}
            for p in doctor.patients]

# ===== رفع الصور =====
@app.post("/upload")
async def upload_images(
    files:       List[UploadFile] = File(...),
    patient_id:  int  = Form(...),
    uploaded_by: str  = Form(...),
    notes:       str  = Form(""),
    db: Session = Depends(get_db)
):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(404, "المريض غير موجود")
    for file in files:
        img_bytes        = await file.read()
        img_array        = bytes_to_array(img_bytes)
        encrypted_array  = encrypt(img_array, SECRET_KEY)
        encrypted_base64 = base64.b64encode(array_to_bytes(encrypted_array)).decode()
        db.add(MedicalImage(
            patient_id=patient.id, file_number=patient.file_number,
            patient_name=patient.name, original_hash=compute_hash(img_array),
            image_data=encrypted_base64, uploaded_by=uploaded_by, notes=notes
        ))
    db.commit()
    return {"success": True, "message": f"تم رفع {len(files)} صورة بنجاح"}

# ===== الصور =====
@app.get("/images")
def get_images(db: Session = Depends(get_db)):
    return [_img_dict(i) for i in
            db.query(MedicalImage).order_by(MedicalImage.uploaded_at.desc()).all()]

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
            "uploaded_by": img.uploaded_by,
            "uploaded_at": img.uploaded_at.strftime("%Y-%m-%d %H:%M"), "notes": img.notes}

@app.get("/view/encrypted/{image_id}")
def view_encrypted(image_id: int, db: Session = Depends(get_db)):
    r = db.query(MedicalImage).filter(MedicalImage.id == image_id).first()
    if not r: raise HTTPException(404, "الصورة غير موجودة")
    return {"image_data": r.image_data, "patient_name": r.patient_name,
            "file_number": r.file_number, "uploaded_by": r.uploaded_by,
            "uploaded_at": r.uploaded_at.strftime("%Y-%m-%d %H:%M"), "notes": r.notes}

@app.get("/view/decrypted/{image_id}")
def view_decrypted(image_id: int, db: Session = Depends(get_db)):
    r = db.query(MedicalImage).filter(MedicalImage.id == image_id).first()
    if not r: raise HTTPException(404, "الصورة غير موجودة")
    enc_array = bytes_to_array(base64.b64decode(r.image_data))
    dec_array = decrypt(enc_array, r.original_hash, SECRET_KEY)
    return {"image_data": base64.b64encode(array_to_bytes(dec_array)).decode(),
            "patient_name": r.patient_name, "file_number": r.file_number,
            "uploaded_by": r.uploaded_by,
            "uploaded_at": r.uploaded_at.strftime("%Y-%m-%d %H:%M"), "notes": r.notes}

# ========================================================
# ===== الأدمن =====
# ========================================================

@app.get("/admin/users")
def get_users(db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username, "name": u.name, "role": u.role}
            for u in db.query(User).all()]

@app.get("/admin/doctors")
def get_doctors(db: Session = Depends(get_db)):
    return [{"id": d.id, "name": d.name}
            for d in db.query(User).filter(User.role == "doctor").all()]


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
    err = validate_password(data.password)
    if err:
        raise HTTPException(400, err)
    db.add(User(username=data.username, password=hash_password(data.password),
                national_id=data.national_id.strip(), role=data.role, name=data.name))
    db.commit()
    return {"success": True, "message": f"تم إضافة {data.name}"}


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, current_admin_id: int, db: Session = Depends(get_db)):
    # منع الأدمن من حذف نفسه
    if user_id == current_admin_id:
        raise HTTPException(400, "لا يمكنك حذف حسابك أنت")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "المستخدم غير موجود")
    db.delete(user)
    db.commit()
    return {"success": True, "message": f"تم حذف {user.name}"}


# إضافة مريض - رقم الملف تلقائي
class PatientCreate(BaseModel):
    name:       str
    doctor_ids: List[int]

@app.post("/admin/patients")
def create_patient(data: PatientCreate, db: Session = Depends(get_db)):
    if not data.doctor_ids:
        raise HTTPException(400, "يجب تحديد دكتور مسؤول")
    doctors = db.query(User).filter(User.id.in_(data.doctor_ids), User.role == "doctor").all()
    if not doctors:
        raise HTTPException(400, "لم يتم العثور على الأطباء")
    # رقم الملف تلقائي
    file_number = generate_file_number(db)
    db.add(Patient(file_number=file_number, name=data.name, doctors=doctors))
    db.commit()
    return {"success": True, "message": f"تم إضافة {data.name}", "file_number": file_number}


# حذف مريض مع كل صوره وارتباطاته
@app.delete("/admin/patients/{patient_id}")
def delete_patient(patient_id: int, db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(404, "المريض غير موجود")
    # cascade="all, delete-orphan" يحذف الصور تلقائياً
    # clear الأطباء المرتبطين
    patient.doctors.clear()
    db.delete(patient)
    db.commit()
    return {"success": True, "message": f"تم حذف {patient.name} وجميع صوره"}


# تعديل أطباء مريض
class PatientUpdate(BaseModel):
    doctor_ids: List[int]

@app.put("/admin/patients/{patient_id}/doctors")
def update_patient_doctors(patient_id: int, data: PatientUpdate, db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(404, "المريض غير موجود")
    if not data.doctor_ids:
        raise HTTPException(400, "يجب تحديد دكتور مسؤول على الأقل")
    doctors = db.query(User).filter(User.id.in_(data.doctor_ids), User.role == "doctor").all()
    if not doctors:
        raise HTTPException(400, "لم يتم العثور على الأطباء")
    patient.doctors = doctors
    db.commit()
    return {"success": True, "message": f"تم تحديث أطباء {patient.name}"}
