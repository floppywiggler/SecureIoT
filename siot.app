from flask import Flask, flash, redirect, render_template, request, session, abort

from scripts.module import Admin, Credentials, DeviceScanner, DatabaseHandler
from scripts import mail
from scripts.utils import getLast15Dates
import os
import threading
import time
import configparser
from datetime import datetime

app = Flask(__name__)
# host='0.0.0.0'
# Bootstrap(app)
loginCount = 0
toDisplay = []
config = configparser.ConfigParser()


@app.route("/graph")
def showGraph():
    if session.get('logged_in'):
        labels = getLast15Dates()
        db = DatabaseHandler()
        values = []
        date_labels = []
        for date in labels:
            values.append(db.getScanResultsVulnerableCountForDate(date))
            date_labels.append(datetime.strptime(date, '%Y-%m-%d').strftime('%b %d %Y'))

        # db = DatabaseHandler()
        # values = db.scanVulFromDB()
        # print(values[0]) # if the oldest scan's first item - vulnerable or not.

        # print(values)
        # scanlist = []
        # for value in values:
        # scanlist.append(value.Vulnerable)
        # print(scanlist[0])
        return render_template('graph.html', values=values, labels=date_labels)
    else:
        return redirect("/")


@app.route("/")
def index():
    if not session.get('logged_in'):
        if (loginCount < 3):
            return render_template('login.html', loginFailed=False)
        else:
            return render_template('retry.html')
    else:
        return render_template('dashboard.html', addDeviceToggle=False, deleteDeviceToggle=False)


@app.route('/login', methods=['POST', 'GET'])
def do_admin_login():
    global loginCount
    if loginCount < 3:
        if admin.verifyCredentials(Credentials(request.form['username'], request.form['password'])):
            session['logged_in'] = True
            loginCount = 0
            return redirect("/")
        else:
            loginCount = loginCount + 1
            if loginCount < 3:
                # flash('wrong password!')
                return render_template('login.html', loginFailed=True, retryOverflow=False)
            else:
                # loginCount = 0
                return render_template('retry.html')
    else:
        #     # wait for 10 seconds.
        #     waitLock(5);
        # loginCount = 0;
        return render_template('retry.html')


@app.route('/retryLogin', methods=['POST'])
def lock_ten_sec():
    global loginCount
    # waitLock(10)
    if (waitLock(10)):
        waitLock(10)
    loginCount = 0;
    return render_template('login.html', loginFailed=False, retryOverflow=False)


@app.route("/about")
def show_about():
    return render_template('about.html')


@app.route("/logout")
def logout():
    session['logged_in'] = False
    return redirect("/")


@app.route("/addDeviceToggle", methods=['GET'])
def showAddDevice():
    if session.get('logged_in'):
        return render_template('addNewCred.html', addDeviceToggle=True, deleteDeviceToggle=True)
    else:
        return redirect("/")


@app.route("/deleteDeviceToggle", methods=['GET'])
def showDeleteDevice():
    if session.get('logged_in'):
        return render_template('deleteCred.html', addDeviceToggle=False, deleteDeviceToggle=True)
    else:
        return redirect("/")


@app.route("/purgeScanResults", methods=['POST'])
def purgeScanResults():
    if session.get('logged_in'):
        try:
            db = DatabaseHandler()
            purge_date = request.form['date']
            db.purgeScanResults(str(purge_date))
            # print(console.log('Date is ' + purge_date))
            return render_template('dashboard.html', resultsPurgedAlert=True)
        except Exception as exception:
            return str(exception)
    else:
        return redirect("/logout")


@app.route("/scanresults", methods=['POST'])
def display_scan_results():
    if session.get('logged_in'):
        ds = DeviceScanner()
        db = DatabaseHandler()

        toDisplay = ds.scanRange(request.form['start_ip'], request.form['end_ip'])
        # print(toDisplay)
        if toDisplay == "invalidIP":
            return render_template('dashboard.html', invalidIP=True)

        else:
            mail_page = render_template('mailer.html', toDisplay=toDisplay)
            # inserted yash's email ID as admin
            # need a list of admins later, to be loaded from the admin db
            # device owners to be handled
            mail.sendMessage([config.get('initialization-parameters', 'adminemail')], mail_page)
            for row in toDisplay:
                if row['vulnerable'] == "Yes":
                    email = db.getEmailIdFromIp(row['ip'])
                    msg = "Your device uses a common/default username & password. Kindly" + \
                          " change it at the earliest. The scan result for your device:<br>" + \
                          "Device: " + row['device'] + \
                          "<br>Protocol: " + row['protocol'] + \
                          "<br>Port: " + str(row['port']) + \
                          "<br>Time when scanned: " + str(row['timestamp'])
                    print(email, msg)
                    mail.sendMessage([email], msg, messageFor="owner")

            return render_template('scanresults.html', toDisplay=toDisplay)
            # will also pass the scan results object into this template.
    else:
        return redirect("/")


@app.route("/register", methods=['GET'])
def registerDisplay():
    global session
    if session.get('logged_in'):
        return render_template('register.html')
    else:
        # session['logged_in'] = False
        return redirect("/logout")
        # return redirect("/logout")


@app.route("/displayAdmins", methods=['GET'])
def displayAdmins():
    global session
    if session.get('logged_in'):
        try:
            db = DatabaseHandler()
            toDisplay = db.getAdminCredentialsFromDB()
            return render_template('viewadmins.html', toDisplay=toDisplay)
        except:
            return "Display Failed..."
    else:
        return redirect("/logout")
