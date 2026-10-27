"""Column classification by header and by content, over every row.

Runs inside the engine: it sees the values but only returns a category, a confidence and counts.
The model never receives what is in here.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum


class Category(str, Enum):
    DOCUMENT = "document"  # national ID, tax ID (NIT), passport
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    ADDRESS = "address"
    BIRTH_DATE = "birth_date"
    CARD = "card"
    BANK_ACCOUNT = "bank_account"
    IP = "ip"
    PLATE = "plate"
    IDENTIFIER = "identifier"  # internal id used to join tables
    FREE_TEXT = "free_text"
    UNCLASSIFIED = "unclassified"  # varied text that could not be classified: the user decides
    NOT_SENSITIVE = "not_sensitive"


class Action(str, Enum):
    DROP = "drop"
    PSEUDONYMIZE = "pseudonymize"
    GENERALIZE = "generalize"
    KEEP = "keep"
    REVIEW = "review"  # the engine does not decide on its own; it asks for confirmation


SUGGESTED_ACTION = {
    Category.DOCUMENT: Action.DROP,
    Category.EMAIL: Action.DROP,
    Category.PHONE: Action.DROP,
    Category.NAME: Action.DROP,
    Category.ADDRESS: Action.DROP,  # without geocoding there is no safe way to generalize it
    Category.BIRTH_DATE: Action.GENERALIZE,
    Category.CARD: Action.DROP,
    Category.BANK_ACCOUNT: Action.DROP,
    Category.IP: Action.DROP,
    Category.PLATE: Action.DROP,
    Category.IDENTIFIER: Action.PSEUDONYMIZE,
    Category.FREE_TEXT: Action.REVIEW,
    Category.UNCLASSIFIED: Action.REVIEW,
    Category.NOT_SENSITIVE: Action.KEEP,
}

# Header vocabulary, in Spanish and English: this is data the files contain, not code
_HEADER_ALIASES: dict[Category, tuple[str, ...]] = {
    Category.DOCUMENT: ("cedula", "documento", "doc", "nit", "rut", "dni", "pasaporte", "identificacion", "cc",
                        "tax_id", "ssn", "passport", "national_id", "id_number"),
    Category.EMAIL: ("correo", "email", "e_mail", "mail"),
    Category.PHONE: ("telefono", "tel", "celular", "movil", "phone", "mobile", "whatsapp", "cell", "telephone"),
    Category.NAME: ("nombre", "nombres", "apellido", "apellidos", "name", "first_name", "last_name", "full_name",
                    "cliente", "empleado", "titular", "paciente", "beneficiario", "afiliado", "contacto", "responsable",
                    "asesor", "vendedor", "estudiante", "usuario", "persona", "referido", "conyuge", "acudiente",
                    "customer", "client", "employee", "holder", "patient", "beneficiary", "contact", "user", "person",
                    "spouse", "guardian"),
    Category.ADDRESS: ("direccion", "address", "domicilio", "residencia", "barrio", "street", "residence",
                       "neighborhood"),
    Category.BIRTH_DATE: ("fecha_nacimiento", "nacimiento", "birth", "birthdate", "dob", "fecha_nac", "date_of_birth"),
    Category.CARD: ("tarjeta", "card", "pan", "credit_card"),
    Category.BANK_ACCOUNT: ("cuenta", "account", "iban", "numero_cuenta", "account_number"),
    Category.IP: ("ip", "ip_address", "direccion_ip"),
    Category.PLATE: ("placa", "plate", "matricula", "license_plate"),
}

# Headers that do not describe a person. It is an allowlist: a header only reaches the model if
# every word is here or in the aliases above, and a text column is only kept by default if its
# header is neutral.
_NEUTRAL_HEADERS = frozenset("""
    monto valor precio total subtotal saldo cantidad unidades unidad edad anio ano puntos costo iva fecha mes dia
    semana trimestre periodo ciudad departamento municipio region pais zona sucursal sede canal segmento categoria
    subcategoria producto servicio plan tipo estado genero sexo estrato descuento cuota plazo tasa interes mora dias
    venta ventas compra compras pedido orden factura codigo cod moneda metodo pago medio origen destino marca modelo
    color talla peso ingreso ingresos egreso gasto utilidad margen meta porcentaje pct ratio activo hoja datos clientes
    registros tabla resultado nivel grupo area cargo
    amount value price balance quantity qty units unit age year points score cost tax date month day week quarter
    period city state country zone branch channel segment category subcategory product service type status gender
    sex discount installment term rate interest days sale sales purchase purchases order invoice code currency method
    payment source destination brand model size weight income expense profit goal percentage active sheet data
    customers records table result level group role department
""".split())
# Names of collections and groups in JSON and YAML: they can be shown and kept as keys, but they say
# nothing about a column's content, so they do not make it neutral
_STRUCTURE_WORDS = frozenset("""
    pedidos ordenes items elementos resultados lineas etiquetas productos servicios facturas detalles metadatos
    empresa empresas contactos telefonos correos direcciones documentos nombres usuarios empleados pacientes
    orders elements results lines tags products services invoices metadata company companies contacts phones
    emails addresses documents names users employees patients
""".split())
_CONNECTORS = frozenset("de del la el los las y por en id no num n x a of the and per".split())
# Free-text column headers: the name can be shown, the content is never kept on its own
_TEXT_HEADERS = frozenset("""
    observaciones observacion comentario comentarios notas nota descripcion detalle mensaje motivo respuesta
    notes note comment comments description details message reason answer observations
""".split())
_NUMERIC = {Category.DOCUMENT, Category.PHONE, Category.CARD}
_IDENTIFYING_WORDS = frozenset(
    part
    for category in (Category.DOCUMENT, Category.PHONE, Category.NAME, Category.CARD, Category.BANK_ACCOUNT,
                     Category.PLATE)
    for alias in _HEADER_ALIASES[category]
    for part in alias.split("_")
    if part not in {"id", "number", "first", "last", "full"}
)

_EMAIL = re.compile(r"^[\w.+\-]+@[\w\-]+(\.[\w\-]+)+$")
_IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_PLATE = re.compile(r"^[A-Z]{3}[ -]?\d{2}[\dA-Z]$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}|^\d{1,2}[/-]\d{1,2}[/-]\d{2,4}")

CONTENT_THRESHOLD = 0.8
FREE_TEXT_LENGTH = 30  # average length from which a column is treated as free text


def _slug(name: str) -> str:
    text = unicodedata.normalize("NFKD", name)
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_nit(value: str) -> bool:
    """Colombian tax ID (NIT): 9 digits plus a check digit (DIAN algorithm)."""
    number = _digits(value)
    if len(number) != 10:
        return False
    body, check = number[:-1], int(number[-1])
    weights = (3, 7, 13, 17, 19, 23, 29, 37, 41)
    remainder = sum(int(d) * w for d, w in zip(reversed(body), weights)) % 11
    return check == (remainder if remainder < 2 else 11 - remainder)


def is_valid_luhn(value: str) -> bool:
    number = _digits(value)
    if not 13 <= len(number) <= 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(number)):
        n = int(digit)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def is_colombian_phone(value: str) -> bool:
    number = _digits(value)
    if number.startswith("57") and len(number) == 12:
        number = number[2:]
    return len(number) == 10 and (number.startswith("3") or number.startswith("60"))


def is_national_id(value: str) -> bool:
    """A Colombian national ID (cédula): 6 to 10 digits, with or without separators."""
    clean = value.strip()
    if not re.fullmatch(r"[\d.\- ]+", clean):
        return False
    number = _digits(clean)
    return 6 <= len(number) <= 10 and not is_colombian_phone(number)


_BY_CONTENT: tuple[tuple[Category, Callable[[str], bool]], ...] = (
    (Category.EMAIL, lambda v: bool(_EMAIL.match(v.strip()))),
    (Category.CARD, is_valid_luhn),
    (Category.IP, lambda v: bool(_IPV4.match(v.strip()))),
    (Category.PLATE, lambda v: bool(_PLATE.match(v.strip().upper()))),
    (Category.PHONE, is_colombian_phone),
    (Category.DOCUMENT, lambda v: is_national_id(v) or is_valid_nit(v)),
)


@dataclass(frozen=True)
class Classification:
    category: Category
    confidence: float  # 0..1
    by_header: bool
    by_content: bool
    rows: int
    empty: int
    unique: int

    @property
    def suggested_action(self) -> Action:
        return SUGGESTED_ACTION[self.category]


def _words(name: str) -> list[str]:
    return [w for w in _slug(name).split("_") if w]


def is_known_header(name: str | None) -> bool:
    """Is this a real header? Only if every word is known vocabulary. A file without a header
    row puts data here ("Ana Ruiz", "Calle 5"): those never pass."""
    if not name or len(name) > 64:
        return False
    words = _words(name)
    known = _NEUTRAL_HEADERS | _STRUCTURE_WORDS | _CONNECTORS | _TEXT_HEADERS | {
        part for aliases in _HEADER_ALIASES.values() for alias in aliases for part in alias.split("_")
    }
    # Short numbers (2026, 1, q3) are fine; a long one could be an ID number used as a header, and
    # next to an identifying word (tarjeta_4242, cuenta_9876) even a short one is part of a value
    identifying = any(w in _IDENTIFYING_WORDS for w in words)
    return (bool(words) and len(words) <= 6 and any(not w.isdigit() for w in words)
            and all(w in known or (w.isdigit() and len(w) <= 4 and not identifying) for w in words))


def _neutral(name: str) -> bool:
    words = [w for w in _words(name) if w not in _CONNECTORS and not w.isdigit()]
    return bool(words) and all(w in _NEUTRAL_HEADERS for w in words)


def by_header(name: str) -> Category | None:
    slug = _slug(name)
    if slug == "id" or slug.startswith("id_") or slug.endswith("_id"):
        return Category.IDENTIFIER
    words = set(slug.split("_"))
    for category, aliases in _HEADER_ALIASES.items():
        if slug in aliases or any(a in words for a in aliases if len(a) > 2) or any(
            a in slug for a in aliases if "_" in a
        ):
            return category
    return None


def classify(name: str, values: Iterable[object]) -> Classification:
    texts = ["" if v is None else str(v) for v in values]
    filled = [t for t in texts if t.strip()]
    rows, empty = len(texts), len(texts) - len(filled)
    unique = len(set(filled))
    hint = by_header(name)

    best: tuple[Category, float] | None = None
    if filled:
        for category, test in _BY_CONTENT:
            share = sum(1 for t in filled if test(t)) / len(filled)
            if share >= CONTENT_THRESHOLD and (best is None or share > best[1]):
                best = (category, share)

    neutral = hint is None and _neutral(name)
    if best and neutral and best[0] in _NUMERIC and best[0] != Category.CARD:
        best = None
    if best and (hint is None or hint == best[0] or hint == Category.IDENTIFIER):
        return Classification(best[0], round(best[1], 2), hint == best[0], True, rows, empty, unique)
    if hint is not None:
        confidence = 0.95 if best and best[0] == hint else 0.7
        return Classification(hint, confidence, True, bool(best), rows, empty, unique)
    if filled and _looks_like_free_text(filled, unique):
        return Classification(Category.FREE_TEXT, 0.6, False, True, rows, empty, unique)
    if not neutral and _textual(filled):
        # Text without a known header (first names, nicknames, neighborhoods...): the user decides
        return Classification(Category.UNCLASSIFIED, 0.5, False, False, rows, empty, unique)
    return Classification(Category.NOT_SENSITIVE, 0.5, False, False, rows, empty, unique)


def _textual(values: list[str]) -> bool:
    if not values:
        return False
    numeric = sum(1 for v in values if re.fullmatch(r"[-+]?[\d.,\s]+", v.strip()) or DATE.match(v.strip()))
    return numeric / len(values) < 0.8


def _looks_like_free_text(values: list[str], unique: int) -> bool:
    average = sum(len(v) for v in values) / len(values)
    with_spaces = sum(1 for v in values if " " in v.strip()) / len(values)
    return average >= FREE_TEXT_LENGTH or (with_spaces > 0.5 and unique / len(values) > 0.5)
