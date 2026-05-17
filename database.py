from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, Table
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import hashlib

engine = create_engine("sqlite:///medical.db", connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


# جدول الربط بين المرضى والأطباء
patient_doctors = Table(
    "patient_doctors", Base.metadata,
    Column("patient_id", Integer, ForeignKey("patients.id")),
    Column("doctor_id",  Integer, ForeignKey("users.id"))
)


class User(Base):
    __tablename__ = "users"
    id          = Column(Integer, primary_key=True)
    username    = Column(String, unique=True, nullable=False)
    password    = Column(String, nullable=False)
    national_id = Column(String, nullable=False)          # ← رقم الهوية الوطنية
    role        = Column(String, nullable=False)
    name        = Column(String, nullable=False)
    patients    = relationship("Patient", secondary=patient_doctors, back_populates="doctors")


class Patient(Base):
    __tablename__ = "patients"
    id          = Column(Integer, primary_key=True)
    file_number = Column(String, unique=True, nullable=False)
    name        = Column(String, nullable=False)
    doctors     = relationship("User", secondary=patient_doctors, back_populates="patients")
    images      = relationship("MedicalImage", back_populates="patient")


class MedicalImage(Base):
    __tablename__ = "images"
    id            = Column(Integer, primary_key=True)
    patient_id    = Column(Integer, ForeignKey("patients.id"), nullable=False)
    file_number   = Column(String, nullable=False)
    patient_name  = Column(String, nullable=False)
    original_hash = Column(String, nullable=False)
    image_data    = Column(Text, nullable=False)
    uploaded_by   = Column(String, nullable=False)
    uploaded_at   = Column(DateTime, default=datetime.utcnow)
    notes         = Column(String, nullable=True)
    patient       = relationship("Patient", back_populates="images")


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    if db.query(User).count() == 0:
        admin  = User(username="admin",      password=hash_password("admin123"), national_id="1000000001", role="admin",     name="مدير النظام")
        radio1 = User(username="radiology1", password=hash_password("1234"),     national_id="1000000002", role="radiology", name="د. أحمد الشمري")
        doc1   = User(username="doctor1",    password=hash_password("1234"),     national_id="1000000003", role="doctor",    name="د. خالد العتيبي")
        doc2   = User(username="doctor2",    password=hash_password("1234"),     national_id="1000000004", role="doctor",    name="د. سارة المالكي")
        db.add_all([admin, radio1, doc1, doc2])
        db.flush()

        p1 = Patient(file_number="P001", name="محمد علي السالم",           doctors=[doc1])
        p2 = Patient(file_number="P002", name="فاطمة عبدالله النجار",       doctors=[doc1, doc2])
        p3 = Patient(file_number="P003", name="عبدالرحمن يوسف القحطاني",  doctors=[doc2])
        db.add_all([p1, p2, p3])
        db.commit()
        print("✅ تم إنشاء قاعدة البيانات")

    db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
