from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
import pytesseract
import io
import re
import dateutil.parser
from datetime import datetime

app = FastAPI()

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Add both variants
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tesseract path (update if installed elsewhere)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

@app.post("/upload-receipt/")
async def upload_receipt(file: UploadFile = File(...)):
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    
    # OCR with improved configuration
    text = pytesseract.image_to_string(image, config='--psm 6')
    print("Extracted Text:\n", text)

    # Extract merchant/business name (usually in the first few lines)
    lines = text.split('\n')
    merchant = lines[0].strip() if lines and lines[0].strip() else "Unknown Merchant"
    
    # Better transaction matching
    transactions = []
    total_amount = 0.0
    
    for line in lines:
        # Match prices with different formats
        matches = re.findall(r'(\b[\w\s]+\b)\s*([£$€]?\s*\d+(?:\.\d{1,2})?)\b', line, re.IGNORECASE)
        if matches:
            for match in matches:
                product = re.sub(r'[^\w\s]', '', match[0]).strip()
                # Skip lines that are likely not products
                if product.lower() in ['total', 'subtotal', 'tax', 'balance', 'change', 'tip']:
                    continue
                    
                price_str = re.sub(r'[^\d.]', '', match[1])
                if price_str:  # Make sure we have valid digits
                    price = float(price_str)
                    transactions.append({
                        "description": product,
                        "amount": price
                    })
        
        # Look for total amount
        total_match = re.search(r'total\s*[:\s]\s*[£$€]?\s*(\d+(?:\.\d{1,2})?)', line, re.IGNORECASE)
        if total_match:
            total_str = re.sub(r'[^\d.]', '', total_match.group(1))
            if total_str:
                total_amount = float(total_str)

    # Better date detection
    date = extract_date(text)

    return {
        "merchant": merchant,
        "date": date,
        "transactions": transactions,
        "total": total_amount
    }

def extract_date(text):
    # Try standard date formats
    date_patterns = [
        r'\b(\d{4}[-/]\d{1,2}[-/]\d{1,2})\b',  # YYYY-MM-DD or YYYY/MM/DD
        r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',  # DD-MM-YYYY or DD/MM/YYYY
        r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{2})\b',  # DD/MM/YY
        r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4}\b',  # Apr 15, 2025
        r'\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{4}\b'   # 15 Apr 2025
    ]
    
    for pattern in date_patterns:
        date_match = re.search(pattern, text, re.IGNORECASE)
        if date_match:
            try:
                # Try to parse the detected date string
                date_str = date_match.group(0)
                parsed_date = dateutil.parser.parse(date_str)
                return parsed_date.strftime('%Y-%m-%d')
            except:
                continue
                
    return ""