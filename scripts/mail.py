import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import configparser


def CreateSMTP(email, password):
    try:
        s = smtplib.SMTP(host='smtp.gmail.com', port=587)
        s.starttls()
        s.login(email, password)
        return s
    except:
        print("\nTry enabling less-secure-apps in your gmail settings")
        return None


def createMessage(body, rec, messageFrom, messageFor="admin"):
    dic = {}
    dic["owner"] = "Scan Results for Device Owner"
    dic["admin"] = "Scan Results for Admin"

    msg = MIMEMultipart('alternative')
    msg['From'] = messageFrom
    msg['To'] = rec
    msg['Subject'] = dic[messageFor]

    data = MIMEText(body, 'html')
    msg.attach(data)
    return msg


def sendMessage(receivers, content, messageFor="admin"):
    config = configparser.ConfigParser()
    config.read_file(open(r'SIOT.config'))
    SIOTscanemail = config.get('initialization-parameters', 'SIOTscanemail')
    SIOTscanpassword = config.get('initialization-parameters', 'SIOTscanpassword')

    # "siotdaemon@gmail.com" "pi@raspberry"
    s = CreateSMTP(SIOTscanemail, SIOTscanpassword)
    if s is None:
        print("Mail cannot be sent as login did not succeed")
        return
    for rec in receivers:
        msg = createMessage(content, rec, messageFor, messageFor)
        try:
            s.send_message(msg)
            print("Mail sent successfully")
        except:
            print("Mail could not be sent")
        del msg
    s.quit()
