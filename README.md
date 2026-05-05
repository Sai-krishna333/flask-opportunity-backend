# flask-opportunity-backend

# 🚀 Flask Opportunity Management Backend

A full-stack backend application built using **Flask (Python)** that handles authentication and opportunity management with a clean API structure and integrated frontend.

---

## 📌 Features

* 🔐 Admin Authentication (Signup / Login / Logout)
* 🔑 Password Reset System (Token-based)
* 📊 Session Management
* 📁 Opportunity Management (CRUD Operations)
* 🗂️ Category-based data handling
* 🌐 REST API architecture
* 🎨 Integrated frontend using Flask templates

---

## 🛠️ Tech Stack

* **Backend:** Flask (Python)
* **Database:** SQLite
* **Frontend:** HTML, CSS, JavaScript
* **Authentication:** Session-based auth
* **Other:** Flask-CORS

---

## 📂 Project Structure

```
TEST1-MAIN-BACKEND/
├── static/
│   ├── admin.css
│   ├── admin.js
│
├── templates/
│   ├── admin.html
│
├── app.py
├── database.db (auto-generated)
├── .gitignore
└── README.md
```

---

## ⚙️ Setup & Run Locally

### 1️⃣ Clone Repository

```
git clone https://github.com/your-username/flask-opportunity-backend.git
cd flask-opportunity-backend
```

---

### 2️⃣ Create Virtual Environment

```
python -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows
```

---

### 3️⃣ Install Dependencies

```
pip install flask flask-cors
```

---

### 4️⃣ Run the Server

```
python app.py
```

---

### 5️⃣ Open in Browser

```
http://localhost:5000
```

---

## 🔌 API Endpoints

### 🔐 Authentication

* `POST /api/signup` → Create account
* `POST /api/login` → Login
* `POST /api/logout` → Logout
* `POST /api/forgot-password` → Request reset
* `POST /api/reset-password/<token>` → Reset password
* `GET /api/me` → Get logged-in user

---

### 📊 Opportunities

* `GET /api/opportunities` → Get all opportunities
* `POST /api/opportunities` → Create new
* `GET /api/opportunities/<id>` → Get one
* `PUT /api/opportunities/<id>` → Update
* `DELETE /api/opportunities/<id>` → Delete

---

## 🔒 Security Features

* Password hashing using SHA-256
* Token-based password reset
* Session-based authentication
* Input validation

---

## 🚀 Future Improvements

* JWT authentication
* Role-based access (Admin/User)
* Deployment (Render / Railway)
* UI enhancements
* Pagination & search

---

## 👨‍💻 Author

**Sai Krishna Vema**

