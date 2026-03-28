from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import Response
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from endesive.pdf import cms
import datetime
import io
import qrcode
import fitz  # PyMuPDF

load_dotenv()

app = FastAPI(title="Firma Digital Service")


def generate_qr_bytes(nombre: str, fecha: str, razon: str) -> bytes:
    """Genera un QR con los datos del firmante y retorna los bytes PNG."""
    data = (
        f"Firmado electrónicamente por: {nombre}\n"
        f"Razón: {razon}\n"
        f"Fecha: {fecha}\n"
        f"Validar con: FirmaEC - Firma Electrónica Ecuador"
    )
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def stamp_qr_on_pdf(
    pdf_bytes: bytes,
    qr_bytes: bytes,
    x: float,
    y: float,
    width: float,
    height: float,
    page: int,
    nombre: str = "",
    fecha: str = "",
) -> bytes:
    """Incrusta el QR como imagen visual en la página indicada del PDF,
    con texto 'Firmado Electrónicamente por' al lado derecho."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    pg = doc[page - 1]
    # fitz usa coordenadas desde la esquina superior izquierda;
    # el PDF usa desde la inferior izquierda → convertir Y
    page_height = pg.rect.height
    top = page_height - y - height
    bottom = page_height - y
    rect = fitz.Rect(x, top, x + width, bottom)
    pg.insert_image(rect, stream=qr_bytes)

    # Texto al lado derecho del QR
    if nombre:
        text_x = x + width + 8
        font_size = 7
        line_height = font_size + 3
        pg.insert_text(
            fitz.Point(text_x, top + font_size),
            "Firmado Electrónicamente por:",
            fontsize=font_size,
            color=(0, 0, 0),
        )
        pg.insert_text(
            fitz.Point(text_x, top + font_size + line_height),
            nombre,
            fontsize=font_size,
            fontname="hebo",
            color=(0, 0, 0),
        )
        pg.insert_text(
            fitz.Point(text_x, top + font_size + line_height * 2),
            "Validar únicamente con FirmaEc",
            fontsize=font_size,
            color=(0, 0, 0),
        )

    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()


@app.post("/sign")
async def sign_pdf(
    pdf: UploadFile,
    p12_file: UploadFile,
    pin: str = Form(...),
    x: float = Form(36),
    y: float = Form(50),
    width: float = Form(120),
    height: float = Form(120),
    page: int = Form(1),
    include_qr: bool = Form(True),
):
    try:
        password = pin.encode("utf-8")
        print(f"[FIRMA] Cargando certificado .p12 recibido...")
        p12_bytes = await p12_file.read()
        p12 = pkcs12.load_key_and_certificates(
            p12_bytes, password, backends.default_backend()
        )
        print(f"[FIRMA] Certificado cargado correctamente")
    except Exception as e:
        print(f"[FIRMA] ERROR al cargar certificado: {e}")
        raise HTTPException(status_code=401, detail="PIN incorrecto o certificado corrupto")

    # Extraer nombre del certificado
    cert = p12[1]
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    nombre = cn_attrs[0].value if cn_attrs else p12_file.filename
    print(f"[FIRMA] Nombre extraído del certificado: {nombre}")

    fecha = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    date = datetime.datetime.utcnow().strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": page - 1,
        "sigbutton": True,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "sigandcertify": True,
        "signaturebox": (x, y, x + width, y + height),
        "signature": "",
        "location": "Ecuador",
        "signingdate": date,
        "reason": "Firma Digital Sistema Médico",
        "password": pin,
    }

    datau = await pdf.read()
    print(f"[FIRMA] PDF recibido: {len(datau)} bytes")

    if include_qr:
        print(f"[FIRMA] Generando QR para: {nombre}")
        qr_bytes = generate_qr_bytes(nombre, fecha, "Firma Digital Sistema Médico")
        datau = stamp_qr_on_pdf(datau, qr_bytes, x, y, width, height, page, nombre, fecha)
        print(f"[FIRMA] QR incrustado en el PDF — nuevo tamaño: {len(datau)} bytes")

    print(f"[FIRMA] Firmando: página {page}, posición x={x} y={y} w={width} h={height}")
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    print(f"[FIRMA] Firma generada: {len(datas)} bytes")

    signed_pdf = datau + datas
    print(f"[FIRMA] PDF firmado listo: {len(signed_pdf)} bytes totales")
    return Response(
        content=signed_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=signed.pdf"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}