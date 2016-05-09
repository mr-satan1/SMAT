from flask import (
    Flask,
    request,
    render_template,
    send_from_directory,
    url_for,
    g,
    jsonify
)
from werkzeug import secure_filename
import os
import yara
import subprocess
import hashlib
import requests
import sqlite3
from contextlib import closing
from ConfigParser import SafeConfigParser

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Configure logging
from logging import Formatter, FileHandler
handler = FileHandler(os.path.join(basedir, 'IsItBad.log'), encoding='utf8')
handler.setFormatter(
    Formatter("[%(asctime)s] %(levelname)-8s %(message)s", "%Y-%m-%d %H:%M:%S")
)
app.logger.addHandler(handler)

# Read and Instantiate Config Parser File
parser = SafeConfigParser()
parser.read('config.ini')

# Config Parser Variables
yaraDir = parser.get('RuleDirectory', 'YarDir')
vtKey = parser.get('VirusTotalAPIKey', 'vtkey')
vtURL = parser.get('VirusTotalURLS', 'reporturl')
smatDB = parser.get('Database', 'db')

# Database schema functions
def initDB():
    with closing(connectDB()) as db:
        with app.open_resource('schema.sql') as schema:
            db.cursor().executescript(schema.read())
        db.commit()

def queryDB(query, args=(), one=False):
    cursor = g.db.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv

def connectDB():
    sqliteDB = sqlite3.connect(smatDB)
    sqliteDB.row_factory = sqlite3.Row
    return sqliteDB

# Security Functions
def importYaraRules():
    global rules
    yaraFiles = {}
    rulesToProcess = os.listdir(yaraDir)
    for events in rulesToProcess:
        if events.endswith('.yar'):
            yaraFiles[events.split('.yar')[0]] = yaraDir + events
    rules = ''
    try:
        rules = yara.compile(filepaths=yaraFiles)
    except yara.SyntaxError:
        return 'Yara problemo!'
    return rules

def testFunction(filename):
    if not rules:
        return 'no rules'
    try:
        matches = rules.match(filename)
    except yara.Error:
        return 'Yara Error!'
        return ''
    if matches:
        results = 'MATCH on the following rules!\n: %s' % reduce(lambda x, y: str(x) + ', ' + str(y), matches)
        app.logger.warning('YARA Match on:' + filename  + results)
    else:
        results = 'No YARA rule matches!'
    return results
    
def hashcrunch(filename):
    md5hash = hashlib.md5()
    with open(filename, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5hash.update(chunk)
    return md5hash.hexdigest()
    
def virusTotalScan(filename):
    # calculate md5 hashsum
    global md5hashcalc
    md5hashcalc = hashcrunch(filename)
    try:
        vtPayload = {'resource': md5hashcalc, 'apikey': vtKey}
        vtRequest = requests.get(vtURL, params=vtPayload)
        vtResponse = vtRequest.json()
        vtResponseCode = int(vtResponse['response_code'])
        if vtResponseCode == 0:
            return 'Nothing in VirusTotal database'
        else:
            return str(vtResponse['permalink'])
    except:
        return 'error'

def dated_url_for(endpoint, **values):
    if endpoint == 'js_static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     'static/js', filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    elif endpoint == 'css_static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     'static/css', filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

@app.before_request
def before_request():
    g.db = connectDB()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

@app.route('/css/<path:filename>')
def css_static(filename):
    return send_from_directory(app.root_path + '/static/css/', filename)


@app.route('/js/<path:filename>')
def js_static(filename):
    return send_from_directory(app.root_path + '/static/js/', filename)

@app.errorhandler(404)
def pageNotFound(e):
    return "404 - This isnt the URL you're looking for...", 404

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploadajax', methods=['POST'])
def upldfile():
    if request.method == 'POST':
        importYaraRules()
        files = request.files['file']
        if files:
            filename = secure_filename(files.filename)
            app.logger.info('Analyzing File: ' + filename)
            updir = os.path.join(basedir, 'upload/')
            files.save(os.path.join(updir, filename))
            fullfilename = os.path.join(updir, filename)
            testme = testFunction(fullfilename)
            vtScan = virusTotalScan(fullfilename)
            file_size = os.path.getsize(fullfilename)
            os.remove(fullfilename)
            app.logger.info('Removed Server Copy: ' + filename)
            g.db.execute('insert into smat (files, submission_date, md5sum, virustotal, yara) values (?, datetime("now"), ?, ?, ?)', (filename, md5hashcalc, vtScan, testme))
            g.db.commit()
            return jsonify(name=filename, size=file_size, md5=md5hashcalc, test=testme, vt=vtScan)
                
if __name__ == '__main__':
    try:
        print 'connecting to SMAT database.'
        connectDB()
        print 'Connected!'
    except:
        print 'Error connect to smat DB'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
