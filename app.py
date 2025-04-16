from flask import Flask, jsonify, render_template, request, redirect, url_for, session # type: ignore
# from flask_session import Session
from collections import deque
import os
import time
import datetime
from datetime import datetime, timedelta
import pytz
import random
import pandas as pd
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from lxml import html as lxml_html

app = Flask(__name__)
app.secret_key = "korpusluteum"  # Güvenlik için gereklidir
# app.config['SESSION_PERMANENT'] = False
# app.config['SESSION_COOKIE_DURATION'] = timedelta(seconds=1)  # 1 saniye sonra oturumu sil
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # 1 gün boyunca oturum geçerli
# # app.permanent_session_lifetime = timedelta(minutes=5)  # Oturum süresi (örnek: 5 dakika)
# app.config["SESSION_TYPE"] = "filesystem"  # Oturumları dosyada tut
# # session(app)
EXCEL_FILE = "users.xlsx"
LOG_FILE = "logins.xlsx"
PAY_FILE = "payments.xlsx"

# Kullanıcı bilgilerini Excel'den yükleme fonksiyonu
def load_users_from_excel():
    df = pd.read_excel(EXCEL_FILE, dtype={
        "username": str, "password": str, "unlimited": str, 
        "full_name": str, "name": str, "surname": str, "email": str, 
        "userIP": str, "registerDate": str, "days_valid": int, 
        "price": int, "paymentDate": str
    })

    users = {}
    unlimited_users = set()
    user_data = {}

    for _, row in df.iterrows():
        username = row.get("username")
        if not username:
            continue  # Eğer username boşsa atla
        
        users[username] = row.get("password", "")

        # Kullanıcının başlangıç tarihini al
        start_date = row.get("paymentDate", "")

        if isinstance(start_date, datetime):
            pass  # Eğer zaten datetime ise, değiştirme
        elif isinstance(start_date, pd.Timestamp):
            start_date = start_date.to_pydatetime()  # Pandas Timestamp'i datetime'a çevir
        elif isinstance(start_date, str) and start_date.strip():
            try:
                start_date = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    start_date = datetime.strptime(start_date, "%d-%m-%Y %H:%M:%S")
                except ValueError:
                    start_date = None  # Hatalı format varsa None yap
        else:
            start_date = None  # Geçersiz bir tarihse None yap

        # Kullanım süresi dolma tarihini hesapla
        if start_date:
            expiry_date = start_date + timedelta(days=int(row.get("daysValid", 0)))
            remaining_days = (expiry_date - datetime.today()).days + 1
        else:
            remaining_days = None  # Geçersiz tarihler için None ata

        user_data[username] = {
            "full_name": row.get("full_name", ""),
            "name": row.get("name", ""),
            "surname": row.get("surname", ""),
            "email": row.get("email", ""),
            "user_ip": row.get("userIP", ""),
            "register_date": row.get("registerDate", ""),
            "days_valid": row.get("daysValid", 0),
            "price": row.get("price", 0),
            "payment_date": row.get("paymentDate", ""),
            "remaining_days": remaining_days 
        }

        # Unlimited kullanıcıları kontrol et
        if str(row.get("unlimited", "")) == "1":
            unlimited_users.add(username)

    return users, unlimited_users, user_data

# Kullanıcı listesini yükle
users, unlimited_users, user_data = load_users_from_excel()

# Oturumları takip eden kullanıcı listesi
active_sessions = {}

@app.route('/', methods=['GET', 'POST'])
def login(): 
    print("login///active_sessions", active_sessions)   
    session.clear()  #  Önceki oturumu temizle
    expired = False             
      
    users, unlimited_users, user_data = load_users_from_excel() # Excel’den güncel olarak al       
    
    # print("users:", users)  
    # print("unlimited_users:", unlimited_users) 
    # print("session.clear():", session)          

    if request.method == 'POST':
        username = str(request.form.get('username')).strip()
        password = str(request.form.get('password')).strip() 
        
        print("users:", users)  
        print("unlimited_users:", unlimited_users) 
        print("session.clear():", session) 
        
        # Admin kontrolü
        # Eğer kullanıcı admin ise, giriş yapmasına izin ver ve tüm kullanıcılara izin ver
        if username == 'a' and password == 'a':  # admin giriş kontrolü
            session.permanent = True
            session['username_a'] = 'a'
            session['is_admin'] = True  # Yönetici olarak oturum açtığını belirt
            return redirect(url_for('admin_dashboard'))  # Yöneticiye yönlendir
        
        # Kullanıcı şifre kontrolü
        if username not in users or users[username] != password:
            # return render_template('login.html', error="Kullanıcı adı veya şifre hatalı!")
            return render_template('login.html', error="Kullanıcı adı veya şifre hatalı!", expired=False)
        
        # Kullanıcı giriş yaptığında log kaydet
        log_login(username)
        
        print("user_data[username]:", user_data[username]) 
        
        # Excel'den alınan kullanıcı verileri   
        # user_info = user_data.get(username, {})
        # full_name = user_info.get("full_name")
        # name = user_info.get("name")
        # remaining_days = user_info.get("remaining_days")
        # password = user_info.get("password")       
        # print("fullname_login:::", full_name) 
        user_info = user_data.get(username, {})
        full_name = user_info.get("full_name")
        remaining_days = user_info.get("remaining_days") 
       
        # Eğer kullanıcı sınırsız giriş hakkına sahip değilse ve kullanım süresi dolmuşsa giriş engellenir
        # if username not in unlimited_users and remaining_days <= 0:
        if username not in unlimited_users and remaining_days is not None and remaining_days <= 0:
            expired = True            
            session.permanent = True  # Oturumun True/False (kalıcı/geçici) olmasını sağla
            session[f'username_{username}'] = username # username id li olarak session'a kaydet 
            session['expired'] = True  # expired durumunu da session'a kaydedelim
            session['user_data'] = user_data # Tüm kullanıcı verileri (dict olarak)
            session['users'] = users # Şifreleri tutan dict   
            print("session_remaining_days <= 0:", session)
            return render_template('login.html', error="Kullanım süreniz dolmuştur!", expired=expired)
       
        # Eğer kullanıcı sınırsız giriş hakkına sahip değilse tek oturum izni ver
        if username not in unlimited_users and username in active_sessions:           
            return render_template('login.html', error="Bu kullanıcı zaten giriş yaptı!", expired=False)

        # Kullanıcı oturumu oluştur
        session.permanent = True
        session[f'username_{username}'] = username
        # session["username"] = username
        session['user_data'] = user_data  # Tüm kullanıcı verileri (dict olarak)
        session['users'] = users  # Şifreleri tutan dict  
        
        # Eğer sınırsız giriş hakkı yoksa aktif oturuma ekle
        # Aktif oturum bilgilerini güncelle
        if username not in unlimited_users:
            active_sessions[username] = {
                "last_activity": datetime.now(),
                "login_time": datetime.now(),
                "full_name": user_info.get('full_name'),
                "name": user_info.get('name'),
                "surname": user_info.get('surname'),
                "email": user_info.get('email'),
                "ip_address": user_info.get('user_ip'),
                "register_date": user_info.get('register_date'),
                "days_valid": user_info.get('days_valid'),
                "price": user_info.get('price'),
                "payment_date": user_info.get('payment_date'),
                "remaining_days": user_info.get('remaining_days')
            }
                       
          
        print("login:::active_sessions:", active_sessions)
        print("login:::username:", username)  
        print("session_login:", session)               

        return redirect(url_for('taslak'))  # Giriş başarılıysa yönlendir
    
    return render_template('login.html', error=None, expired=False) # GET isteğinde login sayfasını döndür

dfLog = pd.read_excel(LOG_FILE)
# Kullanıcı giriş yaptığında log kaydı
def log_login(username):
    # dfLog = pd.read_excel(LOG_FILE)
    global dfLog  # DataFrame'i güncellemek için
    dfLog = dfLog.dropna(how='all')  # Tüm satırı boş olanları at
    dfLog = dfLog.dropna(axis=1, how='all')  # Tüm sütunu boş olanları da at
    new_entry = {"username": username, "login_time": datetime.now(), "logout_time": pd.NaT}
    dfLog = pd.concat([dfLog, pd.DataFrame([new_entry])], ignore_index=True)
    dfLog.to_excel(LOG_FILE, index=False)

# Kullanıcı çıkış yaptığında logout zamanını güncelle
def log_logout(username):    
    # dfLog = pd.read_excel(LOG_FILE)
    global dfLog  # DataFrame'i güncellemek için
    dfLog["logout_time"] = pd.to_datetime(dfLog["logout_time"], errors="coerce")  # Sütunu datetime'a çevir
    # username = int(username)  # username'i int'e çevir
    dfLog["username"] = dfLog["username"].astype(str) # dfLog["username"]'i str'e çevir
    # dfLog.loc[dfLog["username"] == username, "logout_time"] = datetime.now()  # Güncelleme işlemi
    # Sadece logout_time boş (NaT) olan satırları güncelle
    dfLog.loc[(dfLog["username"] == username) & (dfLog["logout_time"].isna()), "logout_time"] = datetime.now()
    dfLog.to_excel(LOG_FILE, index=False)
    
    # print("log_logout(username):", username)
    # print("dfLog_logout_time::", dfLog.loc[dfLog["username"] == username, "logout_time"])
    
    # print(dfLog["username"].dtype)  # username sütununun veri tipini kontrol et
    # print(type(username), username)  # username değişkeninin veri tipini kontrol et
    
@app.route('/admin_dashboard', methods=['GET', 'POST'])  # ✅ POST İzni Verdik
def admin_dashboard():    
    # Yönetici girişi kontrolü
    # if 'username' not in session or session.get('is_admin') is not True:
    if session.get('is_admin') is not True:
        return redirect(url_for('login'))  # Eğer admin girişi yoksa login sayfasına yönlendir
    
    # Kullanıcı verisi ve aktif oturumlar
    total_users = len(users)  # Toplam kullanıcı sayısı
    active_users = len(active_sessions)  # Anlık aktif kullanıcı sayısı
    daily_users = len(set(active_sessions.keys())) # Günlük kullanılan kullanıcı sayısı
    
    # Oturumda geçirilen süreler 
    user_sessions = {
        user: round((datetime.now() - data["last_activity"]).total_seconds() / 60, 2) # Dakika cinsinden hesapla
        for user, data in active_sessions.items()
    }    
       
      
    # Excel'den giriş verilerini oku
    # dfLog = pd.read_excel(LOG_FILE)
    global dfLog  # DataFrame'i güncellemek için    

    # Zaman sütunlarını datetime'a çevir
    dfLog["login_time"] = pd.to_datetime(dfLog["login_time"])
    
    # Son 30 günü al
    now = datetime.now()
    last_n_days = dfLog[dfLog["login_time"] >= (now - pd.Timedelta(days=30))]

    # Günlük bazda grupla
    last_n_days["day"] = last_n_days["login_time"].dt.strftime("%Y-%m-%d")
    daily_counts = last_n_days.groupby("day").size().reset_index(name="user_count")

    # Mevcut günleri listele
    all_days = daily_counts["day"].tolist()

    # Kullanıcının seçtiği günleri al
    selected_days = request.form.get("selected_days")

    if selected_days:
        selected_days = selected_days.split(",")
        print("Seçilen Günler:", selected_days)  # DEBUG
        daily_counts = daily_counts[daily_counts["day"].isin(selected_days)]
    else:
        selected_days = []   
        
        
    # Admin dashboard sayfasına yönlendirirken verileri geçirelim
    return render_template('admin_dashboard.html', 
                            total_users=total_users, 
                            active_users=active_users, 
                            daily_users=daily_users,
                            user_sessions=user_sessions,                        
                            daily_counts=daily_counts.to_dict(orient="records"),  # Günlük veriler
                            all_days=all_days,  # Dropdown için tüm günler
                            selected_days=selected_days
                           )  

# Kullanıcı oturum süresi hesaplama (last_activity)
@app.before_request
def update_last_activity():
    if 'username' in session:
        username = session['username']
        
        if username in active_sessions:  # Eğer oturum açmış bir kullanıcı varsa
            active_sessions[username]['last_activity'] = datetime.now()  # Güncelle
        # else:
        #     # Admin paneline giren kullanıcının da oturum açmasını sağla
        #     active_sessions[username] = {"last_activity": datetime.now()}
        
# @app.before_request
# def make_session_non_permanent():
#     session.permanent = False  # Oturum tarayıcı kapanınca silinsin
#     # session.modified = True  # Her istek geldiğinde session güncellenir
    
@app.route('/taslak')
def taslak():    
    # Session içinden kullanıcıyı bul
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session.get(key)
            break

    if not username:
        return redirect(url_for('login'))
    
    user_data = session.get('user_data', {})
    name = active_sessions.get(username, {}).get("name")
    remaining_days = active_sessions.get(username, {}).get("remaining_days")

    if username in unlimited_users:
        remaining_days = "Sınırsız"

    return render_template('index_flask_46.html', username=username, name=name, remaining_days=remaining_days)
    
@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json(force=True)
    username = data.get("username") if data else None  
    print(f"Gelen logout verisi: {data}")
    print("logout()///username:", username)
    
    if not username:
        return jsonify({"status": "error", "message": "Username alınamadı."}), 400

    # Aktif oturumlardan kaldır
    if username and username in active_sessions:
        del active_sessions[username]

    # Kullanıcıya ait oturumu session'dan temizle
    # for key in list(session.keys()):
    #     if key.startswith("username_") and session[key] == username:
    #         session.pop(key)  # 'username_6' gibi olanı sil
    #         break
    
    # Kullanıcıya ait oturumu session'dan temizle
    session.pop(f'username_{username}', None)
    if 'user_data' in session and username in session['user_data']:
        session['user_data'].pop(username)       
        
    # Logout log kaydı
    log_logout(username)

    print(f"{username} çıkış yaptı. Güncellenmiş active_sessions:", active_sessions)
    print("session_logout:::", session)

    # return jsonify({"status": "success"})
    return jsonify({"status": "success", "message": "Çıkış başarılı"})

# @app.route('/logout', methods=['POST'])
# def logout():
#     data = request.get_json(force=True)
#     username = data.get("username") if data else None  
#     print(f"Gelen logout verisi: {data}")

#     if not username:
#         return jsonify({"status": "error", "message": "Username alınamadı."}), 400

#     # Aktif oturumlardan kaldır
#     if username in active_sessions:
#         del active_sessions[username]

#     # Tüm oturumu sil (güvenli yöntem)
#     session_keys = list(session.keys())
#     for key in session_keys:
#         if username in str(session.get(key, '')) or key.startswith("username_"):
#             session.pop(key, None)

#     # Ekstra temizlik (garanti olsun)
#     session.pop(f'username_{username}', None)
#     session.get('user_data', {}).pop(username, None)
    
#     # Logout log kaydı
#     log_logout(username)

#     return jsonify({"status": "success", "message": "Çıkış başarılı."})

  
@app.route('/user_info')
def user_info():
    return render_template('user_info.html')

@app.route('/save_user_info', methods=['POST'])
def save_user_info():  
    try:
        full_name = request.form['full_name']
        email = request.form['email']
        username = str(request.form['username']).strip()
        password = request.form['password']
        register_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        users, _, _ = load_users_from_excel()

        if username in users:
            return jsonify({
                "status": "error",
                "message": "Bu kullanıcı adı zaten alınmış. Lütfen başka bir tane deneyin!"
            }), 400

        if len(full_name.split(" ")) == 1:
            name = full_name
            surname = None
        else:
            name = " ".join(full_name.split(" ")[:-1])
            surname = full_name.split(" ")[-1]

        # 🔐 Kullanıcı oturum bilgilerini sakla
        session[f'username_{username}'] = username  # id'li şekilde kaydedildi
        # session['password'] = password
        session['expired'] = False  # varsayılan olarak False

        # 👤 Kullanıcı bazlı bilgileri session['user_data'] içinde tutalım
        if 'user_data' not in session:
            session['user_data'] = {}

        session['user_data'][username] = {
            "full_name": full_name,
            "name": name,
            "surname": surname,
            "email": email,
            "register_date": register_date,
            "password": password,
            "user_ip": user_ip,
            "remaining_days": 0  # default başlangıç
        }

        return jsonify({
            "status": "success",
            "message": "Bilgileriniz başarıyla kaydedildi",
            "redirect_url": url_for('purchase'),
            "ip_address": user_ip
        })

    except KeyError as e:
        return jsonify({
            "status": "error",
            "message": f"Eksik veri: {str(e)}"
        }), 400

@app.route('/user_page', methods=["POST"]) 
def user_page():  
    # username_key = session.get('username')
    # data = request.get_json()
    # username_key = data.get('username')  # data-username'den geliyor    
    # username_key = request.args.get('username')  # URL parametresinden alıyoruz
    username_key = request.form.get('username')  # data-username'den geliyor
    print("username_key:", username_key)
    
    if not username_key:
        print("SESSION YOK → login yönlendirmesi.")
        print("session içeriği:", dict(session))
        return redirect(url_for('login'))

    username = session.get(f'username_{username_key}')        # 'mehmet123'
    print("username:", username)
    user_data = session.get('user_data', {})
    users = session.get('users', {})

    if not username or username not in user_data:
        return redirect(url_for('login'))  # Giriş yapılmamışsa login sayfasına yönlendir

    print("session_user_page:", session)
    
    # Kullanıcının bilgilerini user_data içinden al
    user_info = user_data.get(username, {})
    full_name = user_info.get("full_name")
    password = users.get(username)
    email = user_info.get("email")
    register_date = user_info.get("register_date")
    remaining_days = user_info.get("remaining_days")

    # PAY_FILE dosyasını oku   
    pay_df = pd.read_excel(PAY_FILE)
    pay_df['username'] = pay_df['username'].astype(str)

    # Kullanıcının geçmiş ödeme kayıtlarını filtrele
    user_payments = pay_df[pay_df['username'] == username]

    payment_history = []

    for _, row in user_payments.iterrows():        
        start_date = row.get("paymentDate", "")

        if isinstance(start_date, datetime):
            pass
        elif isinstance(start_date, pd.Timestamp):
            start_date = start_date.to_pydatetime()
        elif isinstance(start_date, str) and start_date.strip():
            try:
                start_date = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    start_date = datetime.strptime(start_date, "%d-%m-%Y %H:%M:%S")
                except ValueError:
                    start_date = None
        else:
            start_date = None

        if start_date:
            expiry_date = start_date + timedelta(days=int(row.get("daysValid", 0)))
            remaining_days = (expiry_date - datetime.today()).days + 1
        else:
            remaining_days = None

        if remaining_days is None:
            durum = "Bilinmiyor"
        elif remaining_days < 0:
            durum = "Pasif"
        else:
            durum = f"{remaining_days} gün kaldı"

        payment_history.append({
            "package_name": f"{int(row['daysValid'])} Günlük Paket",
            "payment_amount": f"{row['price']} ₺" if row['price'] > 0 else "Ücretsiz",
            "payment_date": start_date.strftime("%Y-%m-%d %H:%M:%S") if start_date else "Geçersiz Tarih",
            "durum": durum
        })

    return render_template(
        'user_page.html',
        username=username,
        password=password,
        full_name=full_name,
        email=email,
        register_date=register_date,
        payment_history=payment_history
    )

@app.route('/purchase')
def purchase():  
    # session'dan expired durumu alınır
    expired = session.get('expired', False)  # Varsayılan olarak False kabul edilir
    print("expired_purchase:", expired)  
    
    # Tüm kullanıcı oturumlarını al
    user_data_all = session.get('user_data', {})

    # Kullanıcı ID'sini çek
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session[key]
            break

    if not username:
        return redirect(url_for('login'))

    user_data = user_data_all.get(username, {})
    
    if expired:
        remaining_days = user_data.get('remaining_days', None)
        expired = remaining_days is not None and remaining_days <= 0

        print("expired_purchase:", expired)
        print("remaining_days_purchase:", remaining_days)  
        print("session_purchase:", dict(session))          
           
    return render_template('purchase.html', expired=expired)

@app.route('/process_purchase', methods=['POST'])
def process_purchase():  
    # Form verilerini alırken hata olursa log yazalım
    try:
        days_valid = int(request.form['days_valid'])  # Form verisinden gün sayısını al
        price = float(request.form['price'])  # Form verisinden fiyatı al
    except KeyError as e:
        # Eğer form verileri eksikse
        return jsonify({"status": "error", "message": f"Formda eksik veri: {str(e)}"})
    except ValueError as e:
        # Eğer form verileri yanlış türde ise
        return jsonify({"status": "error", "message": f"Geçersiz veri tipi: {str(e)}"})

    print("days_valid_process_purchase:", days_valid)
    print("price_process_purchase:", price)
    # print("username:", username)
    print("session__process_purchase:", session)
    
    # 🔍 Kullanıcı ID'li oturumu bul
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session[key]
            break

    if not username:
        return jsonify({"status": "error", "message": "Oturum açmalısınız."})

    print("username_process_purchase:", username)
    
    # Kullanıcı verilerini çek
    user_data_all = session.get('user_data', {})
    user_data = user_data_all.get(username, {})
    remaining_days = user_data.get('remaining_days', 0)

    # if days_valid == 15 and price == 0 and remaining_days <= 0:
    # Eğer deneme paketi ise ve kullanıcı henüz bu paketi almamışsa:
    if days_valid == 15 and price == 0 and remaining_days <= 0:
        print("Deneme süresi verildi, process_payment(free_trial=True) çağrılıyor...") # Debug log  
              
        # Deneme işlemi sonrası process_payment fonksiyonunu çağırıp yönlendiriyoruz
        return process_payment(free_trial=True)  # Bu çağrı, `freetrial_success`'e yönlendirir.
        # return jsonify({"status": "success", "redirect": url_for('freetrial_success')})

    print("Deneme süresi verilmedi, ödeme sayfasına yönlendiriliyor...")  # Debug log
    return redirect(url_for('payment'))

@app.route('/freetrial_success')
def freetrial_success():
    # Kullanıcı bazlı oturumu bul
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session.get(key)
            break

    if not username:
        return redirect(url_for('process_payment'))  # Oturum bulunamadıysa yönlendir

    user_data_all = session.get('user_data', {})
    user_data = user_data_all.get(username, {})

    full_name = user_data.get('full_name')
    if not full_name:
        return redirect(url_for('process_payment'))

    print("full_name___freetrial_success:", full_name)

    return render_template("freetrial_success.html", full_name=full_name)

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/process_payment', methods=['POST', 'GET'])
def process_payment(free_trial=False):
    print(f"process_payment çağrıldı, free_trial={free_trial}")  # Debug log, free_trial parametresini kontrol et
    
    # Dinamik username key’ini bul
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session[key]
            break

    if not username:
        return redirect(url_for('login'))

    # Kullanıcıya özel verileri al
    user_data = session.get('user_data', {}).get(username, {})
    
    if request.method == 'POST':
        # Session'dan bilgileri alalım    
        full_name = user_data.get('full_name')
        email = user_data.get('email')
        name = user_data.get('name')
        surname = user_data.get('surname')
        register_date = user_data.get('register_date')
        password = user_data.get('password')
        user_ip = user_data.get('user_ip') 
        
        print("session__process_payment:572:", session)
        print("session['user_data']_process_payment:", session['user_data'])
        print("session['user_data'][username]__:process_payment:", session['user_data'][username])
                      
        # Formdan gelen verileri alalım
        try:
            days_valid = int(request.form['days_valid'])
            price = float(request.form['price'])
        except KeyError as e:
            return f"Formda eksik veri var: {str(e)}", 400 
        
        # payment_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")  # Ödeme tarihini kaydet 
        payment_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Ödeme bilgilerini session'a ekleyelim
        # Güncel user_data'yı session’a tekrar yaz
        if username in session['user_data']:
            session['user_data'][username]['days_valid'] = days_valid
            session['user_data'][username]['price'] = price        
         
        # Ödeme logu
        try:
            pay_df = pd.read_excel(PAY_FILE)
            new_payment = pd.DataFrame([{
                "username": username,
                "daysValid": days_valid,
                "price": price,
                "paymentDate": payment_date
            }])
            pay_df = pd.concat([pay_df, new_payment], ignore_index=True)
            pay_df.to_excel(PAY_FILE, index=False)
        except Exception as e:
            print("Ödeme log dosyasına yazılamadı:", e)  
                    
         # Excel dosyasını oku 
        df = pd.read_excel(EXCEL_FILE)            
    
        # Eğer free_trial değilse, username kontrolü yap
        if not free_trial and username in df['username'].astype(str).values:
            # Kullanıcıyı bul ve bilgilerini güncelle
            user_index = df[df['username'].astype(str) == username].index
            
            if not user_index.empty:
                df.loc[user_index, 'daysValid'] = days_valid
                df.loc[user_index, 'price'] = price
                df.loc[user_index, 'paymentDate'] = payment_date
                df.to_excel(EXCEL_FILE, index=False)

                return redirect(url_for('payment_success'), )

            else:
                return jsonify({"status": "error", "message": "Kullanıcı bulunamadı."}), 400
    
            # return jsonify({"status": "error", "message": "Bu kullanıcı adı zaten alınmış."}), 400


        # Yeni kullanıcıyı Excel'e ekle
        new_data = pd.DataFrame([{
            "full_name": full_name,
            "email": email,
            "name": name,
            "surname": surname,
            "registerDate": register_date,
            "daysValid": days_valid,
            "price": price,
            "paymentDate": payment_date,
            "username": username,
            "password": password,
            "userIP": user_ip,
            "unlimited": 0
        }])   
        
        
        # Eğer free_trial seçilmişse ve yeni kullanıcı ise excel dosyasını kaydet 
        # ve freetrial_success yönlendir.
        if free_trial:  
            # print(f"free_trial parametresi: {free_trial}") 
            # print(f"free_trial=full_name:::: {full_name}")          
            df = pd.concat([df, new_data], ignore_index=True)
            df.to_excel(EXCEL_FILE, index=False)
            
            # return jsonify({"status": "success", "redirect": url_for('freetrial_success')})
            return redirect(url_for('freetrial_success'))

                     

        # Excel dosyasını kaydet
        df = pd.concat([df, new_data], ignore_index=True)
        df.to_excel(EXCEL_FILE, index=False)        
        return redirect(url_for('payment_success'))  # ✅ JSON yerine doğrudan yönlendiriyoruz.
    
    return redirect(url_for('payment_success'))

@app.route('/payment_success')
def payment_success():
    # Dinamik username_# anahtarını bul
    username = None
    for key in session.keys():
        if key.startswith("username_"):
            username = session.get(key)
            break

    if not username:
        return redirect(url_for('process_payment'))

    user_data = session.get('user_data', {}).get(username, {})

    if 'full_name' in user_data:
        full_name = user_data.get('full_name')
        days = user_data.get('days_valid')
        price = user_data.get('price')
        print("full_name_payment_success_from_session:::", full_name)
    else:
        try:
            df = pd.read_excel(EXCEL_FILE)
            user_row = df[df['username'].astype(str).str.strip() == str(username).strip()]

            if not user_row.empty:
                full_name = user_row.iloc[0]['full_name']
                days = session['days_valid']
                price = session['price']
                print("full_name_payment_success_from_EXCEL_FILE:::", full_name)
            else:
                return redirect(url_for('process_payment'))
        except Exception as e:
            print("Excel okuma hatası:", e)
            return redirect(url_for('process_payment'))

    return render_template("payment_success.html", full_name=full_name, days=days, price=price)


      
   


UPLOAD_FOLDER = 'uploads'  # Dosyaların kaydedileceği klasör
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# DataFrame'i HTML tablosuna dönüştürme ve render_template_string ile geri döndürme
def dataframe_to_html(df):
    return df.to_html(classes='table table-striped table-bordered', index=False)

@app.route('/takbisOku', methods=['POST'])
def takbisOku():    
    try:    

        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        # Dosyayı belirtilen klasöre kaydet
        file_path = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        file.save(file_path)

        # Chrome Options ayarları
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Headless mod

        # WebDriver başlatma
        driver = webdriver.Chrome(options=chrome_options)
        # driver = webdriver.Chrome()
        # driver = webdriver.Chrome(executable_path='D:\Depo\Sahsi\Drivers\chromedriver.exe', options=chrome_options)


        # Hedef web sayfasını açma
        url = "http://takbisokuma.somee.com/"
        driver.get(url)

        # PDF dosyasını yükleme
        # file_path = os.path.join(os.getcwd(), 'sampleTakbis.pdf')
        # if not os.path.exists(file_path):
        #     raise FileNotFoundError(f"File not found: {file_path}")

        pdf_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, 'MainContent_FileUpload1'))
        )
        pdf_input.send_keys(file_path)

        # Butona tıklama
        button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, 'MainContent_Button1'))
        )
        button.click()

        # 'textarea' içeriğini alma
        textarea = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, 'MainContent_takbisalani'))
        )
        textarea_text = textarea.get_attribute('value')

        # Kaynakları serbest bırak
        driver.quit()
        # os.remove(file_path)

        return jsonify(result=textarea_text)
        # return jsonify({"message": f"File uploaded successfully to {file_path}"}), 200

    except Exception as e:
        # Hata mesajını yazdır
        print("Error in /run_python_code:", e)
        try:
            driver.quit()
        except:
            pass
        return jsonify(error=str(e)), 500  
    
def emsaller(ilce_, mahalle_):  
    
    all_data = []
    page_number = 1
    while True:
        # URL'yi güncelle 
        
        # url = f"https://www.hepsiemlak.com/torbali-torbali-satilik?page={page_number}"
        url = f"https://www.hepsiemlak.com/{ilce_}-{mahalle_}-satilik/daire?page={page_number}"        
        bugun = datetime.datetime.strftime(datetime.datetime.today(), '%d.%m.%Y')      

        df_ua_list = pd.read_excel('user_agent_list.xlsx')
        user_agent_list = df_ua_list.iloc[:,0].values

        df_proxy_list = pd.read_excel('proxy_list.xlsx')
        proxy_list = df_proxy_list.iloc[:,0].values

        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}

        proxies = {"http": random.choice(proxy_list)}    

        response = requests.get(url, headers=headers, proxies=proxies) 
        print("Durum Kodu:", response.status_code)
        
        # İstek başarısız olursa döngüyü kır
        if response.status_code != 200:
            print(f"Error: Could not fetch page {page_number}.")
            break
        
        # HTML ayrıştır
        soup = BeautifulSoup(response.content, "html.parser")
        
        # HTML'yi ayrıştır
        tree = lxml_html.fromstring(response.content)   
        
        
        items = soup.find_all('a', {"class":"img-link"})

        links = []
        link = ["https://www.hepsiemlak.com"+k.get("href") for k in items]
        for k in range(len(link)):
            links.append(link[k])

        links_daire = [i for i in links if "proje" not in i]
        # links_proje_daire = [i for i in links if "proje" in i]
        
        # Veriyi çıkar ve kaydet
        for link in links_daire:        
            all_data.append(link)          
   
        pagination_div = soup.find('div', {"class": "he-pagination"}) 
        #pagination_div = tree.xpath('//div[@class="he-pagination"]')
        # print("pagination_div:", pagination_div)
        
        if pagination_div:
                
            # a etiketini bul
            tag_a = tree.xpath('//div[@class="he-pagination"]/a[last()][contains(@class, "disable")]')
            
            if tag_a != []:
                print(f"No more items found on page {page_number}. Exiting.")
                break
                
            print(f"Page {page_number} scraped.")
            
            # Sonraki sayfaya geç
            page_number += 1
            
        else:
            break

    df_son = pd.DataFrame()
    count_429 = 0
    count_outher = 0

    for link in all_data:
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
        
        proxies = {
            "http": random.choice(proxy_list)
                    }    
        
        response = requests.get(link, headers=headers, proxies=proxies)
                
        if response.status_code == 200:   # Success logic      
            html = response.content
            soup = BeautifulSoup(html, "lxml")
            
            # raw1 = soup.find_all('ul', {"class":"short-property"})
            raw1 = soup.find_all('ul', {"class":"detail-info-location"})

            try:
                il = raw1[0].find_all("li")[0].text.strip()
            except Exception as e:
                il = e
                
            try:
                ilce = raw1[0].find_all("li")[1].text.strip()
            except Exception as e:
                ilce = e
                
            try:
                mahalle = "-".join(raw1[0].find_all("li")[2].text.strip().replace("Mah.", "").split())
            except Exception as e:
                mahalle = e 
                
            try:
                owner = soup.find_all('div', class_='firm-link')[-1].text.strip()
            except Exception as e:
                owner = e   
            
            try:
                localPhone = soup.select_one('em.local_phone + a')['href'].split(":")[1].strip()
            except Exception as e:
                localPhone = e  
            
            try:
                mobilPhone = soup.select_one('em.phone_iphone + a')['href'].split(":")[1].strip() 
            except Exception as e:
                mobilPhone = e     
                

            values = []
            col_name = []
            raw2 = soup.find_all('li', {"class":"spec-item"})
            texts = [i.find("span").text for i in raw2]

            for i in range(0,len(texts)):
                if texts[i] == "Brüt / Net M2":
                    xx = soup.find(string=texts[i]).parent.findNext("span").text.split()[0] + "/" + soup.find(string=texts[i]).parent.findNext("span").findNext("span").text.split()[1]

                else:
                    xx = soup.find(string=texts[i]).parent.findNext("span").text

                values.append(xx)
                col_name.append(texts[i])

            raw3 = soup.find_all('p', {"class":"fz24-text price"})
            try:
                fiyat = raw3[0].text.strip().split()[0]
            except Exception as e:
                fiyat = e

            iimf = [bugun, il, ilce, mahalle, owner, localPhone, mobilPhone, fiyat, link]

            df_link = pd.DataFrame(iimf+values, index = ["veri_tarihi", "il", "ilce", "mahalle", "ilan_sahibi", "localPhone", "mobilPhone", "satis_fiyati", "link"] + col_name).T
            df_son = pd.concat([df_son, df_link], axis = 0)
        
        elif response.status_code == 429:
            count_429 +=1 
            time.sleep(int(response.headers["Retry-After"]))
            
        else:
            print("response.status_code: ", response.status_code)  # Handle other response codes 
            count_outher += 1
        
        # time.sleep(2)
        # time.sleep(random.uniform(1, 3))
        
    #print("Status_code_429 count: ", count_429)
    #print("Status_code_outher count: ", count_outher)
    #df_son = df_son.reset_index().drop_duplicates()
    df_son = df_son.reset_index(drop = True)
    #df_son
    if "Brüt / Net M2" in df_son.columns:
        df_son[["BrutM2", "NetM2"]] = df_son["Brüt / Net M2"].str.split("/", expand=True)
    else:
        print("'Brüt / Net M2' sütunu bulunamadı.")    
    # df_son[["BrutM2","NetM2"]] = df_son["Brüt / Net M2"].str.split("/", expand=True)
    # Pulling the numbers from data of "Number of Floor" column
    # df_son["Kat Sayısı"][df_son["Kat Sayısı"].notnull()] = [i.strip().split()[0] for i in df_son["Kat Sayısı"][df_son["Kat Sayısı"].notnull()]]
    df_son.loc[df_son["Kat Sayısı"].notnull(), "Kat Sayısı"] = [i.strip().split()[0] for i in df_son["Kat Sayısı"][df_son["Kat Sayısı"].notnull()]]
    df_son["Bina Yaşı"] = [str(i).strip().split()[0] for i in df_son["Bina Yaşı"]]
    df_son["CepheSayisi"] = df_son["Cephe"].fillna("singleFacade").apply(lambda x: len(x.split(", ")))
    # display(df_son)

    dfEmsal = df_son[["veri_tarihi", "Son Güncelleme Tarihi", "il","ilce","mahalle","ilan_sahibi", "localPhone", "mobilPhone", "Oda + Salon Sayısı","satis_fiyati","BrutM2","NetM2","Bulunduğu Kat","Bina Yaşı","Isınma Tipi","Kat Sayısı","CepheSayisi", "link"]]
    dfEmsal.columns = ["veri_tarihi", "SonGuncellemeTarihi", 'il', 'ilce', 'mahalle', "ilan_sahibi","sabit_telefon", "mobil_telefon", 'OdaSalonSayisi','satisFiyati', 'BrutM2', 'NetM2', 'BulunduğuKat', 'BinaYasi', 'IsinmaTipi','KatSayisi', 'CepheSayisi', "link"]
        
    #dfEmsal.to_csv(os.path.join("emsaller" , ilce + "_" + mahalle + "_" + bugun + ".csv"), index=False)
    # dfEmsal.to_csv(os.path.join("emsaller" , f"{ilce_}_{bugun}.csv"), index=False)
    dfEmsal.to_csv(os.path.join("emsaller" , f"{ilce_}_{mahalle_}_{bugun}.csv"), index=False)   
    df = dfEmsal
    df = df[df.il == "İzmir"].reset_index(drop=True)
    
    df['sabit_telefon'] = df['sabit_telefon'].fillna("").astype(str)
    df['mobil_telefon'] = df['mobil_telefon'].astype(str)
    df['ilan_sahibi'] = df['ilan_sahibi'].astype(str)

    df = df.replace("'NoneType' object is not subscriptable", "Yok")
    df.ilan_sahibi= df.ilan_sahibi.replace("list index out of range", "Sahibinden")

    df['telefon'] = df.apply(
        lambda row: row['mobil_telefon'] if row['mobil_telefon'] != "Yok" 
        else (row['sabit_telefon'] if row['sabit_telefon'] != "Yok" else row['mobil_telefon']),
        axis=1
    )

    df.drop(columns=["sabit_telefon", "mobil_telefon"], inplace=True)
    cols = list(df.columns)
    col_to_move = cols.pop(cols.index('telefon'))
    cols.insert(4, col_to_move) 
    df = df[cols]


    df.SonGuncellemeTarihi = df.SonGuncellemeTarihi.str.replace("-", ".", regex=False)
    df.satisFiyati = df.satisFiyati.str.replace(".", "").astype(int)
    df.BrutM2 = df.BrutM2.str.replace('.', '', regex=False).astype(int)
    df.NetM2 = df.NetM2.str.replace('.', '', regex=False).astype(int)
    df.KatSayisi = df.KatSayisi.astype(int)
    # df.BinaYasi = df.BinaYasi.fillna("0").str.replace("Sıfır", "0").astype(int)
    df.BinaYasi = pd.to_numeric(df.BinaYasi.fillna("0").replace("Sıfır", "0"), errors="coerce").fillna(0).astype(int)
    # df["birimFiyat"] = (df.satisFiyati / df.NetM2).astype(int)
    df.insert(8, "birimFiyat", (df.satisFiyati / df.NetM2).astype(int))
    bins = [-1, 0, 4, 10, 15, 20, 25, 30, 35, float('inf')]
    labels = ['0', '1-4', '5-10', '11-15', '16-20', '21-25', '26-30', '31-35', '35+']
    # df['BinaYasi_Cat'] = pd.cut(df['BinaYasi'], bins=bins, labels=labels, right=True)
    df.insert(13, "BinaYasi_Cat", pd.cut(df['BinaYasi'], bins=bins, labels=labels, right=True))
    df = df[["il", "ilce", "mahalle", "SonGuncellemeTarihi", "ilan_sahibi", "telefon", "OdaSalonSayisi", "birimFiyat", "satisFiyati", "BrutM2", "NetM2", "BulunduğuKat", "BinaYasi_Cat", "IsinmaTipi", "KatSayisi", "CepheSayisi", "link"]]
    df.columns = ['il', 'ilce', 'mahalle', "İlan Tarihi", "ilan Sahibi","Telefon", "Oda Salon", 'Birim Fiyat', 'Satış Fiyatı', 'BrutM2', 'NetM2', 'Bulunduğu Kat', 'Bina Yaşı', 'Isınma Tipi', 'Bina Kat Sayısı', 'Cephe Sayısı', "link"]
    dff = df.drop(df.columns[-1], axis=1)
    
    grouped1 = df.groupby(['Oda Salon', "Bina Yaşı"])['Birim Fiyat'].agg(['count','mean', "min", "max"]).dropna().astype(int).reset_index()
    grouped2 = df.groupby(["Bina Yaşı",'Oda Salon'])['Birim Fiyat'].agg(['count','mean', "min", "max"]).dropna().astype(int).reset_index()
   
    return [dff, grouped1, grouped2]


def convert_to_english(text):
    turkish_chars = "çğıöşüÇĞİÖŞÜ"
    english_chars = "cgiosuCGIOSU"
    translation_table = str.maketrans(turkish_chars, english_chars)
    
    # Türkçe karakterleri İngilizce karakterlere dönüştür ve küçük harfe çevir
    translated_text = text.translate(translation_table).lower()
    
    # Boşlukları tire (-) ile değiştir
    translated_text = translated_text.replace(" ", "-")
    return translated_text
    
@app.route('/process', methods=['POST'])
def process():
    try:
        print("Gelen JSON:", request.json)  # Gelen JSON'u konsolda görüntüle 
        
        # İstemciden gelen verileri al
        il = request.json.get('il', '').strip()
        ilce = request.json.get('ilce', '').strip()
        mahalle = request.json.get('mahalle', '').strip()

        # Verileri işleyin 
        il_processed = convert_to_english(il)      
        ilce_processed = convert_to_english(ilce)
        mahalle_processed = convert_to_english(mahalle)
        dfEmsal_Processed = emsaller(ilce_processed, mahalle_processed)        
        
        # # DataFrame'i JSON'a dönüştür
        # dfEmsal_Processed_json = dfEmsal_Processed.to_json(orient='columns')  # veya to_json() kullanılabilir
        
        # DataFrame'i HTML tablosuna dönüştürüp render edin
        dfEmsal_html = dataframe_to_html(dfEmsal_Processed[0])
        grouped1_html = dataframe_to_html(dfEmsal_Processed[1])
        grouped2_html = dataframe_to_html(dfEmsal_Processed[2])

        # İşlenmiş verileri JSON formatında döndür
        return jsonify({
            'ilProcessed': il_processed,
            'ilceProcessed': ilce_processed,
            'mahalleProcessed': mahalle_processed,
            "dfEmsalProcessed": dfEmsal_html,
            "grouped1Processed": grouped1_html,
            "grouped2Processed": grouped2_html
        })
    except Exception as e:
        print("Bir hata oluştu:", str(e))  # Hata detayını konsola yazdır
        return jsonify({'error': 'Bir hata oluştu', 'details': str(e)}), 500
      


    
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)  # Eğer 'uploads' klasörü yoksa oluştur
    # app.run(debug=True)
    port = int(os.environ.get("PORT", 10000))  # Render özel port verir
    app.run(host="0.0.0.0", port=port)