import os
import io

def parse_pdf_file(file_stream) -> str:
    """Extract text from PDF file stream using pdfplumber or pypdf with fallback."""
    extracted_text = ""
    file_bytes = file_stream.read()
    file_stream.seek(0)

    # Try pdfplumber first
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            pages_text = [page.extract_text() or "" for page in pdf.pages]
            extracted_text = "\n".join(pages_text).strip()
            if extracted_text:
                return extracted_text
    except Exception as e:
        print(f"[DocumentParser] pdfplumber failed: {e}")

    # Fallback to pypdf
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        pages_text = [page.extract_text() or "" for page in reader.pages]
        extracted_text = "\n".join(pages_text).strip()
        if extracted_text:
            return extracted_text
    except Exception as e:
        print(f"[DocumentParser] pypdf failed: {e}")

    # If binary text has plain ASCII fallback
    try:
        raw_str = file_bytes.decode('ascii', errors='ignore')
        lines = [line.strip() for line in raw_str.splitlines() if len(line.strip()) > 15]
        extracted_text = "\n".join(lines)
    except Exception:
        pass

    return extracted_text or "Could not extract readable text from PDF document."


def parse_docx_file(file_stream) -> str:
    """Extract text from DOCX file stream using python-docx."""
    try:
        import docx
        doc = docx.Document(io.BytesIO(file_stream.read()))
        file_stream.seek(0)
        
        full_text = []
        for para in doc.paragraphs:
            if para.text.strip():
                full_text.append(para.text.strip())
        
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join([cell.text.strip() for cell in row.cells if cell.text.strip()])
                if row_text:
                    full_text.append(row_text)

        extracted = "\n".join(full_text).strip()
        return extracted or "No text content found in DOCX file."
    except Exception as e:
        file_stream.seek(0)
        print(f"[DocumentParser] python-docx error: {e}")
        return f"Error reading DOCX file: {str(e)}"


def parse_ocr_image(file_stream) -> str:
    """Extract text from screenshot image using pytesseract and Pillow."""
    try:
        from PIL import Image, ImageEnhance
        import pytesseract

        img_bytes = file_stream.read()
        file_stream.seek(0)
        
        image = Image.open(io.BytesIO(img_bytes)).convert('L') # Convert to grayscale
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)

        text = pytesseract.image_to_string(image)
        text = text.strip()
        return text if text else "OCR scanning completed, but no text could be recognized from the image."
    except Exception as e:
        file_stream.seek(0)
        print(f"[DocumentParser] OCR Tesseract exception: {e}")
        return "OCR engine unavailable or image resolution too low for text extraction."


def extract_text_from_upload(file_obj, filename: str) -> tuple[str, str]:
    """Inspect filename extension and extract text accordingly."""
    if not file_obj or not filename:
        return "", "Text"

    ext = filename.lower().split('.')[-1]
    
    if ext == 'pdf':
        return parse_pdf_file(file_obj), "PDF Document"
    elif ext in ['docx', 'doc']:
        return parse_docx_file(file_obj), "DOCX Document"
    elif ext in ['png', 'jpg', 'jpeg', 'bmp', 'webp']:
        return parse_ocr_image(file_obj), "OCR Screenshot"
    else:
        try:
            content = file_obj.read().decode('utf-8', errors='ignore')
            file_obj.seek(0)
            return content, "Text File"
        except Exception:
            return "", "Unknown"
