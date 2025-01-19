from flask import Flask, request, jsonify
import pandas as pd
import matplotlib
import re
from googlesearch import search
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
from flask_cors import CORS
import warnings

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)
matplotlib.use('Agg')

app = Flask(__name__)
CORS(app)

# Load dataset
df = pd.read_csv('Web_Extension_API/malicious_phish.csv', nrows=20000)

# Feature extraction functions
def contains_ip_address(url):
    return 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url) else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 0 if hostname and re.search(re.escape(hostname), url) else 1

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    return urlparse(url).path.count('/')

def no_of_embed(url):
    return urlparse(url).path.count('//')

def shortening_service(url):
    return 1 if re.search(r'bit\.ly|goo\.gl|t\.co|tinyurl|ow\.ly', url) else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(url)

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    return 1 if re.search(r'PayPal|login|signin|bank|account|free|ebay', url) else 0

def digit_count(url):
    return sum(1 for char in url if char.isdigit())

def letter_count(url):
    return sum(1 for char in url if char.isalpha())

def fd_length(url):
    path = urlparse(url).path.split('/')
    return len(path[1]) if len(path) > 1 else 0

# Apply feature extraction to dataset
df['use_of_ip'] = df['url'].apply(contains_ip_address)
df['abnormal_url'] = df['url'].apply(abnormal_url)
df['count.'] = df['url'].apply(count_dot)
df['count-www'] = df['url'].apply(count_www)
df['count@'] = df['url'].apply(count_atrate)
df['count_dir'] = df['url'].apply(no_of_dir)
df['count_embed_domian'] = df['url'].apply(no_of_embed)
df['short_url'] = df['url'].apply(shortening_service)
df['count-https'] = df['url'].apply(count_https)
df['count-http'] = df['url'].apply(count_http)
df['count%'] = df['url'].apply(count_per)
df['count?'] = df['url'].apply(count_ques)
df['count-'] = df['url'].apply(count_hyphen)
df['count='] = df['url'].apply(count_equal)
df['url_length'] = df['url'].apply(url_length)
df['hostname_length'] = df['url'].apply(hostname_length)
df['sus_url'] = df['url'].apply(suspicious_words)
df['count-digits'] = df['url'].apply(digit_count)
df['count-letters'] = df['url'].apply(letter_count)
df['fd_length'] = df['url'].apply(fd_length)

# Encode labels
lb_make = LabelEncoder()
df['url_type'] = lb_make.fit_transform(df['type'])

# Split dataset
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@', 'count_dir', 'count_embed_domian',
        'short_url', 'count-https', 'count-http', 'count%', 'count?', 'count-', 'count=',
        'url_length', 'hostname_length', 'sus_url', 'fd_length', 'count-digits', 'count-letters']]
y = df['url_type']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train models
clf_rf = RandomForestClassifier(n_estimators=100, random_state=42)
clf_rf.fit(X_train, y_train)
clf_svm = svm.SVC(kernel='linear')
clf_svm.fit(X_train, y_train)

# Feature extraction for prediction
def extract_features(url):
    return [
        contains_ip_address(url), abnormal_url(url), count_dot(url), count_www(url),
        count_atrate(url), no_of_dir(url), no_of_embed(url), shortening_service(url),
        count_https(url), count_http(url), count_per(url), count_ques(url),
        count_hyphen(url), count_equal(url), url_length(url), hostname_length(url),
        suspicious_words(url), fd_length(url), digit_count(url), letter_count(url)
    ]

def predict_url_type(url):
    features = extract_features(url)
    prediction_rf = clf_rf.predict([features])[0]
    prediction_svm = clf_svm.predict([features])[0]
    return lb_make.inverse_transform([prediction_rf])[0], lb_make.inverse_transform([prediction_svm])[0]

def google_search(query):
    try:
        return list(search(query, num_results=5, pause=2))
    except Exception as e:
        return [f"Error fetching results: {e}"]

# Prediction endpoint
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is missing'}), 400

    prediction_rf, prediction_svm = predict_url_type(url)
    google_results = google_search(url)
    result_str = "URL IS SAFE!" if prediction_rf in ['benign', 'defacement'] else "URL IS MALICIOUS!"

    return jsonify({
        'prediction_rf': prediction_rf,
        'prediction_svm': prediction_svm,
        'result_str': result_str,
        'google_results': google_results
    })

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
