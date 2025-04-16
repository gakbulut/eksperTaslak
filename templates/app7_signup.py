from flask import Flask, jsonify, render_template, request, redirect, url_for, session # type: ignore
import os
import time
import datetime
from datetime import datetime, timedelta
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
# app.permanent_session_lifetime = timedelta(minutes=5)  # Oturum süresi (örnek: 5 dakika)
EXCEL_FILE = "users.xlsx"

# Kullanıcı bilgilerini Excel'den yükleme fonksiyonu
def load_users_from_excel():
    # df = pd.read_excel(EXCEL_FILE)  # Excel dosyasını oku
    df = pd.read_excel(EXCEL_FILE, dtype={"username": str, "password": str, "unlimited": str}) # Excel dosyasını oku , "start_date": str
    users = {}
    unlimited_users = set()
    user_data = {}


    for _, row in df.iterrows():
        users[row["username"]] = row["password"]
        user_data[row["username"]] = {
            "name": row["name"],  # Kullanıcı adı
            "days_valid": row["days_valid"],
            "start_date": datetime.strptime(str(row["start_date"]).split(" ")[0], "%Y-%m-%d"),
        }
        if row["unlimited"] == "1":
            unlimited_users.add(row["username"])

    return users, unlimited_users, user_data

# Kullanıcı listesini yükle
users, unlimited_users, user_data = load_users_from_excel()

# Oturumları takip eden kullanıcı listesi
active_sessions = {}

@app.route('/', methods=['GET', 'POST'])
def login():
    global users, unlimited_users, user_data
    users, unlimited_users, user_data = load_users_from_excel()  # Excel’den güncelle

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Kullanıcı şifre kontrolü
        if username not in users or users[username] != password:
            return render_template('login.html', error="Kullanıcı adı veya şifre hatalı!")

        # Kullanıcının başlangıç tarihini Excel’den al
        start_date = user_data[username]["start_date"]
        expiry_date = start_date + timedelta(days=user_data[username]["days_valid"])
        remaining_days = (expiry_date - datetime.today()).days
        # if username in unlimited_users:
        #     remaining_days = 99999
        # else:
        #     remaining_days = (expiry_date - datetime.today()).days

        # Kullanım süresi dolmuşsa giriş engellenir
        if remaining_days < 0:
            return render_template('login.html', error="Bu kullanıcının kullanım süresi dolmuştur!")

        # Eğer kullanıcı sınırsız giriş hakkına sahip değilse tek oturum izni ver
        if username not in unlimited_users and username in active_sessions:
            return render_template('login.html', error="Bu kullanıcı zaten giriş yaptı!")

        # Kullanıcıyı oturuma kaydet
        session.permanent = True
        session['username'] = username
        session['remaining_days'] = remaining_days

        # Eğer sınırsız giriş hakkı yoksa aktif oturuma ekle
        if username not in unlimited_users:
            active_sessions[username] = True  

        return redirect(url_for('taslak'))  # Giriş başarılıysa yönlendir
    
    return render_template('login.html', error=None)

@app.route('/taslak')
def taslak():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    name = user_data[username]["name"]

    if username in unlimited_users:
        remaining_days = "Sınırsız"
    else:
        remaining_days = session['remaining_days']

    return render_template('index_flask_45.html', username=username, name=name, remaining_days=remaining_days)
    
@app.route('/logout')
def logout():
    username = session.get('username')
    if username and username in active_sessions:
        del active_sessions[username]  # Kullanıcıyı aktif oturumlardan çıkar
    session.pop('username', None)  # Oturumu sil
    session.pop('remaining_days', None)  # Kalan günleri temizle
    return redirect(url_for('login'))

@app.route('/close_session', methods=['POST'])
def close_session():
    username = session.get('username')
    if username and username in active_sessions:
        del active_sessions[username]  # Kullanıcıyı aktif oturumlardan çıkar
    session.pop('username', None)  # Oturumu kapat
    session.pop('remaining_days', None)  # Kalan günleri temizle
    return '', 204  # Boş yanıt döndür

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ad = request.form['ad']
        soyad = request.form['soyad']
        start_date = request.form['start_date']
        days_valid = int(request.form['days_valid'])

        # Yeni kullanıcıyı Excel'e ekleyelim
        try:
            df = pd.read_excel(EXCEL_FILE)
        except FileNotFoundError:
            df = pd.DataFrame(columns=["username", "password", "name", "start_date", "days_valid"])

        new_user = pd.DataFrame([{
            "username": username,
            "password": password,
            "ad": ad,
            "soyad": soyad,
            "start_date": start_date,
            "days_valid": days_valid
        }])

        df = pd.concat([df, new_user], ignore_index=True)
        df.to_excel(EXCEL_FILE, index=False)

        return redirect(url_for('login'))  # Kayıt sonrası login sayfasına yönlendir

    return render_template('signup.html')





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
    app.run(debug=True)