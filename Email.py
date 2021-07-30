import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.mime.multipart import MIMEMultipart
import datetime
import time


class Email(object):
    def __init__(self, configuration):
        self.emailObject = smtplib.SMTP()
        if configuration.get('smtp_host') and configuration.get('smtp_port') \
                and configuration.get('mail_sender') and configuration.get('mail_recipient'):
            self.emailObject.connect(configuration.get('smtp_host'), configuration.get('smtp_port'))
            self.message = MIMEMultipart()
            self.message['From'] = Header(configuration.get('mail_sender'), 'utf-8')
            self.message['To'] = Header(configuration.get('mail_recipient'), 'utf-8')
            self.sender = configuration.get('mail_sender')
            self.receiver = configuration.get('mail_recipient').split(';')

        else:
            self.emailObject.connect("mail.coscon.com", 25)
            self.message = MIMEMultipart()
            self.message['From'] = Header('13671653851@163.com', 'utf-8')
            self.message['To'] = Header('13671653851@163.com', 'utf-8')
            self.sender = '13671653851@163.com'
            self.receiver = ['13671653851@163.com']

        self.message['Subject'] = Header(
            'CVE search --%s' % time.strftime('%Y-%m-%d', datetime.datetime.now().timetuple()))
        self.message.attach(MIMEText('Dear, \n\n\tAttached is the CVE search result for today.\n\n\tThanks.', 'plain', 'utf-8'))

    def addAttachment(self, filepath):
        attachment = MIMEText(open('result.xlsx', 'rb').read(), 'base64', 'utf-8')
        attachment["Content-Type"] = 'application/octet-stream'
        attachment["Content-Disposition"] = 'attachment; filename="result--%s.xlsx"' % (
            time.strftime('%Y-%m-%d', datetime.datetime.now().timetuple()))
        self.message.attach(attachment)

    def send_email(self):
        self.emailObject.sendmail(self.sender, self.receiver, self.message.as_string())
