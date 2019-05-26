from flask import Flask, flash, redirect, render_template, request, session, abort
from scripts.module import Admin, Credentials, DeviceScanner, DatabaseHandler, DeviceExploit
from scripts import mail
from scripts.utils import getLast15Dates
import threading
import time
import configparser
from datetime import datetime

siot = Flask(__name__)
# host='0.0.0.0'
# Bootstrap(siot)
loginCount = 0
toDisplay = []
config = configparser.ConfigParser()


@siot.route("/graph")
def showGraph():
    if session.get('logged_in'):
        labels = getLast15Dates()
        db = DatabaseHandler()
        values = []
        date_labels = []
        for date in labels:
            values.append(db.getScanResultsVulnerableCountForDate(date))
            date_labels.append(datetime.strptime(date, '%Y-%m-%d').strftime('%b %d %Y'))

        #db = DatabaseHandler()
        #values = db.scanVulFromDB()
        #print(values[0]) # if the oldest scan's first item - vulnerable or not.

        #print(values)
        scanlist = []
        #for value in values:
        #    scanlist.append(value.Vulnerable)
        #    print(scanlist[0])

        return render_template('graph.html', values=values, labels=date_labels)
    else:
        return redirect("/")


@siot.route("/")
def index():
    if not session.get('logged_in'):
        if (loginCount < 3):
            return render_template('login.html', loginFailed=False)
        else:
            return render_template('retry.html')
    else:
        return render_template('dashboard.html', addDeviceToggle=False, deleteDeviceToggle=False)


@siot.route('/login', methods=['POST', 'GET'])
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


@siot.route('/retryLogin', methods=['POST'])
def lock_ten_sec():
    global loginCount
    # waitLock(10)
    if (waitLock(10)):
        waitLock(10)
    loginCount = 0
    return render_template('login.html', loginFailed=False, retryOverflow=False)


@siot.route("/about")
def show_about():
    return render_template('about.html')


@siot.route("/logout")
def logout():
    session['logged_in'] = False
    return redirect("/")


@siot.route("/addDeviceToggle", methods=['GET'])
def showAddDevice():
    if session.get('logged_in'):
        return render_template('addNewCred.html', addDeviceToggle=True, deleteDeviceToggle=True)
    else:
        return redirect("/")


@siot.route("/deleteDeviceToggle", methods=['GET'])
def showDeleteDevice():
    if session.get('logged_in'):
        return render_template('deleteCred.html', addDeviceToggle=False, deleteDeviceToggle=True)
    else:
        return redirect("/")


@siot.route("/purgeScanResults", methods=['POST'])
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


@siot.route("/scanresults", methods=['POST'])
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


@siot.route("/exploitresults", methods=['POST'])
def display_exploit_scan_results():
    if session.get('logged_in'):
        ds = DeviceExploit()
        db = DatabaseHandler()

        toDisplay = ds.scanRange(request.form['start_ip'], request.form['end_ip'])
        # print(toDisplay)
        if toDisplay == "invalidIP":
            return render_template('dashboard.html', invalidIP=True)

        else:
            mail_page = render_template('mailer.html', toDisplay=toDisplay)
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

            return render_template('exploitresults.html', toDisplay=toDisplay)
            # will also pass the scan results object into this template.
    else:
        return redirect("/")


@siot.route("/register", methods=['GET'])
def registerDisplay():
    global session
    if session.get('logged_in'):
        return render_template('register.html')
    else:
        # session['logged_in'] = False
        return redirect("/logout")
        # return redirect("/logout")


@siot.route("/displayAdmins", methods=['GET'])
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


@siot.route("/deregisterAdmin", methods=['POST'])
def deregisterAdmin():
    global session
    if session.get('logged_in'):
        # return redirect("/")
        #  try to deregister admin
        #  1. take username/email from form.
        # new_admin = Admin(request.form['username'],request.form['email'],Credentials(request.form['username'], request.form['password']))
        #  2. try adding it to db.
        # try:
        db = DatabaseHandler()
        uOE = request.form['usernameOrEmailID']
        db.deleteAdmin(uOE)
        return render_template("/", showAdminRemovedAlert=True)
        #  also display added alert instead of a new page.
    # except:
    # return "Deregister Failed..."
    #  3. display success/failure message.
    else:
        return redirect("/logout")


@siot.route("/registerAdmin", methods=['POST'])
def registerAdmin():
    global session
    if session.get('logged_in'):
        # return redirect("/")
        #  try to register admin
        #  1. take username, password and email from form.
        new_admin = Admin(request.form['username'], request.form['email'],
                          Credentials(request.form['username'], request.form['password']))
        #  2. try adding it to db.
        try:
            db = DatabaseHandler()
            db.insertNewAdmin(new_admin)
            return render_template("/addedAdmin.html")
        except:
            return "Registration Failed..."
        #  3. display success/failure message.
    else:
        return redirect("/logout")


@siot.route("/viewcredentials", methods=['GET'])
def display_credentials():
    if session.get('logged_in'):
        db = DatabaseHandler()
        toDisplay = db.getCredentialsFromDB()
        return render_template('viewcredentials.html', toDisplay=toDisplay)
    else:
        return redirect("/")


@siot.route("/viewscanhistory", methods=['GET'])
def view_scan_history():
    if session.get('logged_in'):
        db = DatabaseHandler()
        toDisplay = db.getScanResultsFromDB()
        return render_template('viewscanhistory.html', toDisplay=toDisplay)
    else:
        return redirect("/")


@siot.route("/notifyuser", methods=['POST'])
def notifyUser():
    if session.get('logged_in'):
        # call notify user from service layer.
        # implement client side error handling.
        flash('Device Owner Notified!...')
        return render_template('dashboard.html', addDeviceToggle=False)
    else:
        return redirect("/")


@siot.route("/addNewDevice", methods=['POST'])
def addNewDevice():
    # handle exceptions and return siotropriate message
    # call add new device method of service layer.
    #
    if session.get('logged_in'):
        db = DatabaseHandler()
        db.insertIntoDefaultCredentials(request.form['username'], request.form['password'])
        return render_template('addNewCred.html', addDeviceToggle=False, deleteDeviceToggle=False, addedDevice=True)
    else:
        return redirect("/")


@siot.route("/deleteDevice", methods=['POST'])
def deleteDevice():
    # handle exceptions and return appropriate message
    # call add new device method of service layer.
    #
    if session.get('logged_in'):
        db = DatabaseHandler()
        db.deleteFromDefaultCredentials(request.form['username'], request.form['password'])
        return render_template('deleteCred.html', addDeviceToggle=False, deleteDeviceToggle=False, deletedDevice=True)
    else:
        return redirect("/")


lock = threading.Lock()
cond = threading.Condition(threading.Lock())


def waitLock(timeout):
    with cond:
        current_time = start_time = time.time()
        while current_time < start_time + timeout:
            if lock.acquire(False):
                return True
            else:
                cond.wait(timeout - current_time + start_time)
                current_time = time.time()
    return False


if __name__ == "__main__":
    loginFailed = False
    loginCount = 0
    retryOverflow = False
    admin = Admin("Emil Sørbrøden", "siotdaemon@gmail.com", Credentials("admin", "password"))
    # protocolScanner = ProtocolScanner("Kunal Protocol" , "9997", "Kunal Host" )
    # myPort = protocolScanner.getPortNumber()
    siot.secret_key = "itavisen"  # os.urandom(12)

    config.read_file(open(r'SIOT.config'))
    host = config.get('initialization-parameters', 'host')
    port = int(config.get('initialization-parameters', 'port'))
    #######
    # Create and run siot
    siot.run(debug=True, host=host, port=port)
    # create_siot()
