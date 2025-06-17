# 💸 FinTrack

FinTrack is a smart personal finance tracking web application. It allows users to track their daily expenses, upload receipts, and automatically extract transaction details using Optical Character Recognition (OCR). Built with a modern tech stack for seamless user experience and performance.

## 🚀 Features

- 📥 Upload receipts in image format
- 🧠 Automatic extraction of products and prices using OCR
- 💼 Maintain a transaction history
- 📊 Visualize your expense data (upcoming feature)
- 🔐 Secure and fast backend built with FastAPI
- 🌐 Simple and responsive frontend

## 🛠️ Tech Stack

### Frontend:
- HTML5, CSS3, JavaScript
- Bootstrap (for styling and responsiveness)

### Backend:
- Python + FastAPI
- OCR via Tesseract or similar library
- Uvicorn (ASGI server)
- SQLite or JSON for data storage

### Tools:
- VS Code
- Git & GitHub
- Jupyter Notebooks (for prototyping OCR logic)

## 📷 How It Works

1. User uploads a receipt image.
2. OCR processes the image to extract:
   - Item names
   - Prices
3. Extracted data is parsed and added to the transaction list.
4. User can view and manage expenses through the web interface.

## 📁 Project Structure
-fintrack/
-  backend/
-     ├── main.py              # FastAPI backend
-     ├── ocr_utils.py         # OCR and parsing logic
-     └── receipts/            # Uploaded receipt images
-   frontend/
-      ├── index.html
-      ├── transactions.html
-      └── assets/
-      ├── styles.css
-      └── script.js
-    ├── data/
-    └── transactions.json    # Stored transaction data
-     ── requirements.txt

---

## 🧪 Setup & Run Locally

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/yourusername/fintrack.git](https://github.com/yourusername/fintrack.git)
    cd fintrack
    ```

2.  **Set up a virtual environment**
    ```bash
    python -m venv venv
    source venv/bin/activate        # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the backend**
    ```bash
    uvicorn backend.main:app --reload
    ```

5.  **Open the frontend**
    Open `frontend/index.html` in your browser manually.

---

## 📌 To-Do

* Add user authentication
* Integrate expense graphs
* Export data as CSV
* Cloud deployment (Render / Vercel / Railway)

---

## 🤝 Contributers

-Kavide Manichander
- kavidemanichander@gmail.com

-Abdul Raheem
- abdul.raheem27678@gmail.com
